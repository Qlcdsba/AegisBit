// Aho-Corasick Multi-Pattern Automaton
// High-performance string matching engine for concurrent detection of hundreds of attack signatures in O(N) time.

///|
/// A node in the Aho-Corasick Trie.
pub(all) struct AcNode {
  mut fail : Int
  output : Array[Int]
  transitions : Array[(UInt16, Int)]
}

///|
/// Creates a new empty Trie node.
pub fn AcNode::new() -> AcNode {
  { fail: 0, output: [], transitions: [], }
}

///|
/// Finds child node index for a given UTF-16 code unit.
pub fn AcNode::find_child(self : AcNode, ch : UInt16) -> Int? {
  let mut i = 0
  let len = self.transitions.length()
  while i < len {
    let (c, next_idx) = self.transitions[i]
    if c == ch {
      return Some(next_idx)
    }
    i = i + 1
  }
  None
}

///|
/// Adds a transition to child node.
pub fn AcNode::add_child(self : AcNode, ch : UInt16, next_idx : Int) -> Unit {
  self.transitions.push((ch, next_idx))
}

///|
/// Aho-Corasick Multi-Pattern Automaton.
pub(all) struct AcAutomaton {
  nodes : Array[AcNode]
  patterns : Array[String]
}

///|
/// Creates a new Aho-Corasick automaton initialized with root node.
pub fn AcAutomaton::new() -> AcAutomaton {
  let root = AcNode::new()
  { nodes: [root], patterns: [], }
}

///|
/// Adds a pattern keyword and associates it with a rule index.
pub fn AcAutomaton::insert(
  self : AcAutomaton,
  pattern : String,
  rule_idx : Int,
) -> Unit {
  if pattern.length() == 0 {
    return
  }
  let mut current_idx = 0
  let mut i = 0
  let pat_len = pattern.length()
  while i < pat_len {
    let ch = pattern[i]
    match self.nodes[current_idx].find_child(ch) {
      Some(next_idx) => current_idx = next_idx
      None => {
        let new_node = AcNode::new()
        let new_idx = self.nodes.length()
        self.nodes.push(new_node)
        self.nodes[current_idx].add_child(ch, new_idx)
        current_idx = new_idx
      }
    }
    i = i + 1
  }
  self.nodes[current_idx].output.push(rule_idx)
  self.patterns.push(pattern)
}

///|
/// Builds failure transitions across the automaton using BFS.
pub fn AcAutomaton::build_failure_links(self : AcAutomaton) -> Unit {
  let queue : Array[Int] = []
  let mut q_head = 0

  // Level 1 children fail to root (0)
  let root_trans = self.nodes[0].transitions
  let mut i = 0
  while i < root_trans.length() {
    let (_, child_idx) = root_trans[i]
    self.nodes[child_idx].fail = 0
    queue.push(child_idx)
    i = i + 1
  }

  // BFS traversal for deeper levels
  while q_head < queue.length() {
    let curr_idx = queue[q_head]
    q_head = q_head + 1

    let curr_trans = self.nodes[curr_idx].transitions
    let mut j = 0
    while j < curr_trans.length() {
      let (ch, child_idx) = curr_trans[j]
      queue.push(child_idx)

      // Find fail target for child_idx
      let mut f = self.nodes[curr_idx].fail
      let mut found_fail = false
      let mut target_fail = 0

      while !found_fail {
        match self.nodes[f].find_child(ch) {
          Some(next_f) => {
            target_fail = next_f
            found_fail = true
          }
          None =>
            if f == 0 {
              target_fail = 0
              found_fail = true
            } else {
              f = self.nodes[f].fail
            }
        }
      }

      self.nodes[child_idx].fail = target_fail

      // Merge output from failure link
      let fail_outputs = self.nodes[target_fail].output
      let mut k = 0
      while k < fail_outputs.length() {
        self.nodes[child_idx].output.push(fail_outputs[k])
        k = k + 1
      }

      j = j + 1
    }
  }
}

///|
/// A matched hit containing pattern rule index and end position in text.
pub(all) struct AcMatch {
  rule_index : Int
  end_pos : Int
}

///|
/// Scans input text and returns all matched rule indices and positions.
pub fn AcAutomaton::matches(
  self : AcAutomaton,
  text : String,
) -> Array[AcMatch] {
  let results : Array[AcMatch] = []
  let mut current_idx = 0
  let mut i = 0
  let text_len = text.length()

  while i < text_len {
    let ch = text[i]
    let mut next_opt = self.nodes[current_idx].find_child(ch)

    while next_opt is None && current_idx != 0 {
      current_idx = self.nodes[current_idx].fail
      next_opt = self.nodes[current_idx].find_child(ch)
    }

    match next_opt {
      Some(next_idx) => current_idx = next_idx
      None => current_idx = 0
    }

    let node_outputs = self.nodes[current_idx].output
    if node_outputs.length() > 0 {
      let mut m = 0
      while m < node_outputs.length() {
        results.push({ rule_index: node_outputs[m], end_pos: i, })
        m = m + 1
      }
    }

    i = i + 1
  }

  results
}

///|
/// Compiles a set of pattern strings into an optimized Aho-Corasick automaton.
pub fn AcAutomaton::compile(patterns : Array[String]) -> AcAutomaton {
  let ac = AcAutomaton::new()
  let mut i = 0
  while i < patterns.length() {
    ac.insert(patterns[i], i)
    i = i + 1
  }
  ac.build_failure_links()
  ac
}
