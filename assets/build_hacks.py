import sys
import os

# read file specified as first argument
with open(sys.argv[1], 'r') as f:
    content = f.read()
game = sys.argv[2].upper()

jump_tables = {}
# find `jpt_` jump tables
current_jpt = None
current_jpt_entries = -1
for line in content.splitlines():
    if line.startswith('jpt_'):
        if current_jpt_entries >= 0:
            jump_tables[current_jpt] = current_jpt_entries
        current_jpt_entries = 0
    elif not line.startswith('    ') and current_jpt_entries >= 0:
        jump_tables[current_jpt] = current_jpt_entries
        current_jpt_entries = -1
    elif current_jpt_entries == -1:
        continue
    if current_jpt_entries >= 0:
        if "DCD" in line:
            current_jpt_entries += 1
            current_jpt = int(line.split(" - ")[1].split(" ")[0], 16) - 0x7100000000

print("use crate::{hacks::hacks::Hacks};")
print()
print(f"const JUMP_TABLES: [(u64, usize); {len(jump_tables)}] = [")
for addr, entries in jump_tables.items():
    print(f"    (0x{addr:08x}, {entries}),")
print("];")

print(f"""
pub struct {game}Hacks {{}}
impl {game}Hacks {{
    pub fn new() -> anyhow::Result<Self> {{
        Ok({game}Hacks {{}})
    }}
}}
impl Hacks for {game}Hacks {{
    fn get_jump_tables(&self) -> Vec<(u64, usize)> {{
        JUMP_TABLES.to_vec()
    }}
}}
""")
