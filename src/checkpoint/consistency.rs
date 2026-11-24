//! 旧检查点前缀到新检查点前缀的一致性证明。

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{leaf_hash, merkle_root, node_hash};
use crate::hash::Hash;

pub const SCHEMA: u32 = 1;

type Coord = (usize, usize);
type CoordSet = BTreeSet<Coord>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofNode {
    pub level: usize,
    pub index: usize,
    #[serde(with = "hash_hex")]
    pub hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProof {
    pub schema: u32,
    pub from_size: usize,
    pub to_size: usize,
    #[serde(with = "hash_hex")]
    pub old_root: Hash,
    #[serde(with = "hash_hex")]
    pub new_root: Hash,
    pub subtrees: Vec<ProofNode>,
    pub siblings: Vec<ProofNode>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConsistencyError {
    #[error("一致性证明形状不合法：{0}")]
    BadShape(String),
    #[error("一致性证明验证失败：{0}")]
    Invalid(String),
}

pub fn consistency_proof(
    leaves: &[Hash],
    from_size: usize,
) -> Result<ConsistencyProof, ConsistencyError> {
    if from_size > leaves.len() {
        return Err(ConsistencyError::BadShape(format!(
            "旧前缀 {from_size} 超过新前缀 {}",
            leaves.len()
        )));
    }
    let to_size = leaves.len();
    let (subtree_coords, sibling_coords) = proof_coordinates(from_size, to_size);
    let levels = merkle_levels(leaves);
    let old_root = merkle_root(&leaves[..from_size]);
    let new_root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .unwrap_or_else(|| merkle_root(&[]));
    Ok(ConsistencyProof {
        schema: SCHEMA,
        from_size,
        to_size,
        old_root,
        new_root,
        subtrees: nodes_at(&levels, &subtree_coords)?,
        siblings: nodes_at(&levels, &sibling_coords)?,
    })
}

pub fn verify_consistency(proof: &ConsistencyProof) -> Result<bool, ConsistencyError> {
    if proof.schema != SCHEMA {
        return Err(ConsistencyError::BadShape(format!(
            "schema 应为 {SCHEMA}，实际是 {}",
            proof.schema
        )));
    }
    if proof.from_size > proof.to_size {
        return Err(ConsistencyError::BadShape(
            "旧前缀不能比新前缀长".to_string(),
        ));
    }
    let (expected_subtrees, expected_siblings) = proof_coordinates(proof.from_size, proof.to_size);
    let actual_subtrees = node_coords(&proof.subtrees)?;
    let actual_siblings = node_coords(&proof.siblings)?;
    if actual_subtrees != expected_subtrees.into_iter().collect::<Vec<_>>() {
        return Err(ConsistencyError::Invalid(
            "旧前缀子树坐标与声明尺寸不符".to_string(),
        ));
    }
    if actual_siblings != expected_siblings.into_iter().collect::<Vec<_>>() {
        return Err(ConsistencyError::Invalid(
            "兄弟节点坐标与声明尺寸不符".to_string(),
        ));
    }
    let subtrees = node_map(&proof.subtrees)?;
    let old_root = reconstruct_root(proof.from_size, &subtrees)?
        .ok_or_else(|| ConsistencyError::Invalid("旧前缀根无法重建".to_string()))?;
    if old_root != proof.old_root {
        return Err(ConsistencyError::Invalid(
            "旧前缀根与子树哈希不符".to_string(),
        ));
    }

    let mut all_nodes = subtrees;
    for node in &proof.siblings {
        insert_node(&mut all_nodes, (node.level, node.index), node.hash)?;
    }
    let new_root = reconstruct_root(proof.to_size, &all_nodes)?
        .ok_or_else(|| ConsistencyError::Invalid("新前缀根无法重建".to_string()))?;
    Ok(new_root == proof.new_root)
}

fn proof_coordinates(from_size: usize, to_size: usize) -> (CoordSet, CoordSet) {
    let decomposed_size = if from_size == 0 { to_size } else { from_size };
    let subtrees: CoordSet = subtree_coordinates(decomposed_size).into_iter().collect();
    let mut siblings = CoordSet::new();
    let root_level = tree_levels(to_size);
    for &(mut level, mut index) in &subtrees {
        while level < root_level {
            let sibling = (level, index ^ 1);
            if sibling.1 < level_count(to_size, level) && !subtrees.contains(&sibling) {
                siblings.insert(sibling);
            }
            level += 1;
            index /= 2;
        }
    }
    (subtrees, siblings)
}

fn subtree_coordinates(size: usize) -> Vec<(usize, usize)> {
    let mut remaining = size;
    let mut position = 0usize;
    let mut out = Vec::new();
    while remaining > 0 {
        let level = (usize::BITS - 1 - remaining.leading_zeros()) as usize;
        let width = 1usize << level;
        out.push((level, position / width));
        position = position
            .checked_add(width)
            .ok_or_else(|| ConsistencyError::BadShape("前缀尺寸溢出".to_string()))
            .expect("journal length cannot overflow usize");
        remaining -= width;
    }
    out
}

fn tree_levels(size: usize) -> usize {
    if size <= 1 {
        0
    } else {
        (usize::BITS - (size - 1).leading_zeros()) as usize
    }
}

fn level_count(size: usize, level: usize) -> usize {
    size.div_ceil(1usize << level)
}

fn merkle_levels(leaves: &[Hash]) -> Vec<Vec<Hash>> {
    let mut levels = vec![leaves.iter().copied().map(leaf_hash).collect::<Vec<_>>()];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let level = levels.last().expect("non-empty levels");
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(node_hash(pair[0], pair.get(1).copied().unwrap_or(pair[0])));
        }
        levels.push(next);
    }
    levels
}

fn nodes_at(
    levels: &[Vec<Hash>],
    coords: &BTreeSet<(usize, usize)>,
) -> Result<Vec<ProofNode>, ConsistencyError> {
    coords
        .iter()
        .map(|&(level, index)| {
            let hash = levels
                .get(level)
                .and_then(|nodes| nodes.get(index))
                .copied()
                .ok_or_else(|| {
                    ConsistencyError::BadShape(format!("节点坐标 ({level}, {index}) 越界"))
                })?;
            Ok(ProofNode { level, index, hash })
        })
        .collect()
}

fn node_coords(nodes: &[ProofNode]) -> Result<Vec<(usize, usize)>, ConsistencyError> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        let coord = (node.level, node.index);
        if out.contains(&coord) {
            return Err(ConsistencyError::Invalid(format!(
                "节点坐标 ({}, {}) 重复",
                node.level, node.index
            )));
        }
        if out.last().is_some_and(|previous| *previous >= coord) {
            return Err(ConsistencyError::Invalid(format!(
                "节点坐标 ({}, {}) 未按规范顺序排列",
                node.level, node.index
            )));
        }
        out.push(coord);
    }
    Ok(out)
}

fn node_map(nodes: &[ProofNode]) -> Result<BTreeMap<(usize, usize), Hash>, ConsistencyError> {
    let mut out = BTreeMap::new();
    for node in nodes {
        insert_node(&mut out, (node.level, node.index), node.hash)?;
    }
    Ok(out)
}

fn insert_node(
    nodes: &mut BTreeMap<(usize, usize), Hash>,
    coord: (usize, usize),
    hash: Hash,
) -> Result<(), ConsistencyError> {
    if let Some(existing) = nodes.insert(coord, hash)
        && existing != hash
    {
        return Err(ConsistencyError::Invalid(format!(
            "节点坐标 ({}, {}) 给出两个不同哈希",
            coord.0, coord.1
        )));
    }
    Ok(())
}

fn reconstruct_root(
    size: usize,
    nodes: &BTreeMap<(usize, usize), Hash>,
) -> Result<Option<Hash>, ConsistencyError> {
    if size == 0 {
        return Ok(Some(merkle_root(&[])));
    }
    let mut known = nodes.clone();
    for level in 0..tree_levels(size) {
        let count = level_count(size, level);
        let current = known
            .iter()
            .filter_map(|(&(node_level, index), &hash)| {
                (node_level == level).then_some((index, hash))
            })
            .collect::<Vec<_>>();
        for (index, hash) in current {
            if index >= count {
                return Err(ConsistencyError::Invalid(format!(
                    "第 {level} 层节点 {index} 越界（该层只有 {count} 个）"
                )));
            }
            if index % 2 == 1 {
                continue;
            }
            let sibling = index ^ 1;
            let parent_hash = if sibling < count {
                let sibling_hash = known.get(&(level, sibling)).copied().ok_or_else(|| {
                    ConsistencyError::Invalid(format!(
                        "第 {level} 层缺兄弟 {sibling}，无法重建父节点"
                    ))
                })?;
                node_hash(hash, sibling_hash)
            } else {
                node_hash(hash, hash)
            };
            insert_node(&mut known, (level + 1, index / 2), parent_hash)?;
        }
    }
    Ok(known.get(&(tree_levels(size), 0)).copied())
}

mod hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::hash::Hash;

    pub fn serialize<S: Serializer>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hash.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
        let text = String::deserialize(deserializer)?;
        Hash::from_hex(&text).ok_or_else(|| serde::de::Error::custom("哈希必须是 64 位十六进制"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(size: usize) -> Vec<Hash> {
        (0..size)
            .map(|index| Hash::of(format!("event-{index}").as_bytes()))
            .collect()
    }

    #[test]
    fn consistency_proofs_verify_for_all_small_prefixes() {
        for size in 1..=65 {
            let leaves = leaves(size);
            for from in 0..=size {
                let proof = consistency_proof(&leaves, from).unwrap();
                verify_consistency(&proof).unwrap_or_else(|err| {
                    panic!("size={size}, from={from}, proof={proof:?}: {err}")
                });
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_tampering_and_wrong_shapes() {
        let leaves = leaves(37);
        let proof = consistency_proof(&leaves, 13).unwrap();
        assert!(verify_consistency(&proof).unwrap());

        let mut bad_hash = proof.clone();
        bad_hash.subtrees[0].hash = Hash::of(b"tampered");
        assert!(!verify_consistency(&bad_hash).unwrap_or(false));

        let mut bad_sibling = proof.clone();
        bad_sibling.siblings[0].hash = Hash::of(b"tampered");
        assert!(!verify_consistency(&bad_sibling).unwrap_or(false));

        let mut duplicate = proof.clone();
        duplicate.siblings.push(duplicate.siblings[0].clone());
        assert!(verify_consistency(&duplicate).is_err());

        let mut extra = proof.clone();
        extra.siblings.push(ProofNode {
            level: 100,
            index: 0,
            hash: Hash::of(b"extra"),
        });
        assert!(verify_consistency(&extra).is_err());

        let mut wrong_size = proof;
        wrong_size.from_size += 1;
        assert!(verify_consistency(&wrong_size).is_err());
    }

    #[test]
    fn consistency_proof_rejects_reordered_and_foreign_subtrees() {
        let old = leaves(13);
        let mut foreign = leaves(14);
        foreign[12] = Hash::of(b"foreign");
        let proof = consistency_proof(&leaves(37), 13).unwrap();
        assert!(proof.subtrees.len() > 1);
        assert!(proof.siblings.len() > 1);

        let mut reordered_subtrees = proof.clone();
        reordered_subtrees.subtrees.reverse();
        assert!(verify_consistency(&reordered_subtrees).is_err());

        let mut reordered_siblings = proof.clone();
        reordered_siblings.siblings.reverse();
        assert!(verify_consistency(&reordered_siblings).is_err());

        let old_proof = consistency_proof(&old, 13).unwrap();
        let foreign_root = merkle_root(&foreign);
        let mut forged = old_proof;
        forged.new_root = foreign_root;
        assert!(!verify_consistency(&forged).unwrap());
    }

    #[test]
    fn empty_old_prefix_still_verifies_new_root() {
        let proof = consistency_proof(&leaves(17), 0).unwrap();
        assert!(verify_consistency(&proof).unwrap());

        let mut forged = proof;
        forged.new_root = Hash::of(b"forged-empty-prefix-root");
        assert!(!verify_consistency(&forged).unwrap());
    }

    #[test]
    fn consistency_proof_stays_small_for_large_prefixes() {
        let leaves = leaves(10_000);
        let proof = consistency_proof(&leaves, 4_321).unwrap();
        assert!(verify_consistency(&proof).unwrap());
        assert!(proof.subtrees.len() + proof.siblings.len() < 64);
    }
}
