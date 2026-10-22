"""
CyberSage AI — Playbook Parser

Reads Markdown playbook files from the knowledge_base/playbooks/ directory,
parses them into structured sections (chunks), and returns clean text chunks
with their metadata (playbook_id, title, section heading) for ChromaDB ingestion.
"""

import os
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger("cybersage.rag.parser")


@dataclass
class PlaybookChunk:
    """
    A single chunked passage from a security playbook with its metadata.
    """
    chunk_id: str          # e.g., "PB-001-SSH-BRUTE__section_2"
    playbook_id: str       # e.g., "PB-001-SSH-BRUTE"
    playbook_title: str    # e.g., "SSH Brute Force and Credential Stuffing Response"
    section: str           # e.g., "Key Indicators of Compromise"
    text: str              # The passage text content


def _extract_playbook_id_from_filename(filename: str) -> str:
    """Extract the playbook ID from the markdown filename stem."""
    return os.path.splitext(filename)[0]  # e.g. "PB-001-SSH-BRUTE"


def parse_playbook_file(filepath: str) -> list[PlaybookChunk]:
    """
    Parse a single playbook Markdown file into section-level chunks.
    
    Strategy: 
    - The first H1 heading (`# Title`) is used as the playbook title.
    - Each H2 heading (`## Section`) marks the start of a new chunk.
    - The text under that heading until the next H2 is the chunk body.
    - Minimum chunk length of 50 chars is enforced to skip trivial fragments.
    """
    filename = os.path.basename(filepath)
    playbook_id = _extract_playbook_id_from_filename(filename)

    with open(filepath, "r", encoding="utf-8") as f:
        raw = f.read()

    # Extract H1 title
    title_match = re.search(r"^#\s+(.+)$", raw, re.MULTILINE)
    playbook_title = title_match.group(1).strip() if title_match else playbook_id

    # Split file into sections based on H2 headings
    sections = re.split(r"\n## ", raw)
    chunks: list[PlaybookChunk] = []

    for idx, section_text in enumerate(sections[1:], start=1):  # skip preamble before first ##
        lines = section_text.strip().split("\n")
        section_heading = lines[0].strip().lstrip("#").strip()
        body = "\n".join(lines[1:]).strip()

        if len(body) < 50:
            logger.debug(f"Skipping short section '{section_heading}' in {playbook_id}")
            continue

        chunk_id = f"{playbook_id}__section_{idx}"
        chunks.append(PlaybookChunk(
            chunk_id=chunk_id,
            playbook_id=playbook_id,
            playbook_title=playbook_title,
            section=section_heading,
            text=body,
        ))

    logger.info(f"Parsed {len(chunks)} chunks from '{playbook_title}' ({playbook_id})")
    return chunks


def parse_all_playbooks(playbooks_directory: str) -> list[PlaybookChunk]:
    """
    Walk the playbooks directory, parse all .md files, and return all chunks.
    """
    all_chunks: list[PlaybookChunk] = []

    if not os.path.isdir(playbooks_directory):
        logger.error(f"Playbooks directory not found: {playbooks_directory}")
        return all_chunks

    md_files = sorted([f for f in os.listdir(playbooks_directory) if f.endswith(".md")])

    if not md_files:
        logger.warning(f"No .md playbook files found in: {playbooks_directory}")
        return all_chunks

    for filename in md_files:
        filepath = os.path.join(playbooks_directory, filename)
        try:
            chunks = parse_playbook_file(filepath)
            all_chunks.extend(chunks)
        except Exception as e:
            logger.error(f"Failed to parse playbook '{filename}': {e}")

    logger.info(f"Total parsed chunks from {len(md_files)} playbooks: {len(all_chunks)}")
    return all_chunks
