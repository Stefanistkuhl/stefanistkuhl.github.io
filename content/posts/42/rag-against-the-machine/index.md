+++
title = 'RAG Against the Machine'
context = '42 project · local search and RAG'
date = '2026-08-13T21:00:00+02:00'
description = 'Building a fast local search and RAG system for source-code repositories.'
categories = ["projects", "42"]
tags = ["python", "sqlite", "tree-sitter", "search", "rag"]
draft = true
+++

<!--
INTRO — ~150-250 words

- This started as a 42 project.
- The task: search a source repository and answer questions about it.
- More importantly: return the exact source locations supporting the answer.
- I decided to build the retrieval/indexing parts directly instead of using
  a big RAG framework.
- Tease the interesting bits:
  Tree-sitter, SQLite FTS5, weird UTF-8 offsets, concurrency, etc.

DON'T:
- explain what an LLM is
- give a generic 5-paragraph explanation of RAG
- list every project feature
-->


## The basic idea

<!--
~150-250 words

Very briefly explain:

repository
-> index source files
-> retrieve chunks relevant to question
-> give chunks to local model
-> answer + source locations

Mention that most of the interesting work turned out to be retrieval/indexing,
not model generation.
-->

<!-- TODO: Add the high-level architecture diagram before publishing. -->

<!--
DIAGRAM HERE.

Keep this diagram simpler than the giant inspiration diagram.

I'd show roughly:

                    INDEXING
repository
    |
    v
file discovery
    |
    v
Tree-sitter / text chunking
    |
    v
search enrichment
    |
    v
SQLite + FTS5
    ^
    |
inotify / incremental updates


                    QUERYING
question
    |
    v
FTS5 / BM25
    |
    v
code-aware reranking
    |
    v
top-k source chunks
    |
    v
Qwen
    |
    v
answer + sources

The article explains the details; the diagram should only provide orientation.
-->


## What even is a chunk of source code?

<!--
~300-450 words

PROBLEM:
You can't give an entire large repository to a model.

OBVIOUS SOLUTION:
Split every N characters/tokens.

WHY THAT'S BAD FOR CODE:
You can cut a function/class/declaration in half.
The resulting chunk has less useful context.

YOUR SOLUTION:
Tree-sitter gives you syntactic structure.
Use functions/classes/declarations/etc. as natural boundaries.

Mention:
- different languages need slightly different structural nodes
- oversized definitions still have to be split
- preserve gaps such as imports/comments/module variables
- fall back to text chunking when parsing isn't reliable

Include ONE tiny source example.
-->

```python
# tiny illustrative example only
def load_config():
    ...

def start_server():
    ...

<!--
Explain: ideally these become two meaningful chunks rather than an arbitrary
character window that happens to end halfway through start_server().
-->

### The UTF-8 problem I didn't expect

<!--
~200-300 words

This is a good "weird bug/problem" story.

Tree-sitter positions = UTF-8 byte offsets.
Python string slicing = Unicode character offsets.

An emoji/accent/non-ASCII character means these positions aren't necessarily
the same.

Explain why this REALLY mattered:
the evaluator expected exact source character ranges.

Show the invariant, not 40 lines of ByteCharacterMap implementation.
-->

```python
chunk.text == complete_file[
    chunk.first_character_index:chunk.last_character_index
]
```

<!--
Then explain ByteCharacterMap in prose:
- construct mapping between byte positions and Python character positions
- convert parser ranges
- validate every final chunk

Maybe show:

"a🚀b"
 ^ one character
 ^ four UTF-8 bytes

No need for more code.
-->

## Why SQLite FTS5?

<!--
~300-400 words

START WITH EXPECTATION:
For a RAG project, I expected embeddings/vector search to be central.

OBSERVATION:
Source code contains unusually useful lexical signals:
- function/type names
- filenames
- paths
- identifiers
- technical terms from the question

DECISION:
Try FTS5 + BM25 first.

Explain briefly:
SQLite stores files/chunks AND gives full-text search.

Don't explain BM25 mathematically.
-->

### Making lexical search less stupid for code

<!--
~250-350 words

Raw text search still has problems.

Example:

question:
"Where is the LoRA adapter loaded?"

code:
load_lora_adapter
OpenAIServing
some/path/lora_model_runner.py

Explain your search representation:
- path
- structural context
- identifier decomposition
- snake_case -> words
- CamelCase -> words

IMPORTANT IDEA:
Enrich SEARCH TEXT, not returned evidence.

Maybe visualize:

original source:
    load_lora_adapter(...)

search text:
    path/to/file.py
    load_lora_adapter
    load lora adapter
    ...

returned evidence:
    load_lora_adapter(...)

Then mention small path/identifier-aware reranking after BM25.
-->

## Making indexing fast enough

<!--
~300-400 words

Start with the naive version:

for every file:
    read
    parse
    insert chunks
    update index

Then explain what actually mattered:

- asyncio coordinates work / bounded queue
- blocking filesystem work can run in threads
- CPU-heavy parsing can use processes
- database writes are batched
- fresh import can rebuild FTS once instead of maintaining it row-by-row

DO NOT turn this into an asyncio tutorial.

Talk about WHY each thing exists.
-->

```text
files
  |
  v
bounded queue
  |
  +--> worker
  +--> worker
  +--> worker
          |
          v
      batched writes
          |
          v
        SQLite
```

<!--
This could be a SECOND MINI DIAGRAM instead of code.
I'd probably use text/diagram here rather than a Python snippet.
-->

### Reindexing one changed file instead of everything

<!--
~150-250 words

Explain incremental indexing:

- remember metadata for indexed files
- cheap checks first (size, mtime, settings/version)
- hash only when needed
- unchanged files get skipped
- changed file gets reindexed

Then mention inotify:
Linux watcher feeds changed paths back into the asyncio loop.

This is a nice place for ONE tiny real code snippet IF you like the implementation:

loop.add_reader(...)

But only use it if there's something worth explaining.
Otherwise just link the source.
-->

## SQLite ended up doing nearly everything

<!--
~200-300 words

Short reflective section.

SQLite became:
- file metadata store
- exact chunk store
- full-text index
- incremental indexing state
- transaction boundary

Talk about why having one local transactional DB was convenient.

Mention bulk insert / FTS rebuild optimization.

Don't dump CREATE TABLE statements unless one particular schema trick matters.
-->

## Did it actually work?

<!--
~200-300 words

RESULTS TABLE HERE.

Use the measured run from your README.

Explain:
- what Recall@5 means in ONE sentence
- docs result
- code result
- index time
- search time

Then INTERPRET it:
simple lexical retrieval + code-specific enrichment was much stronger than
you expected.

Be clear benchmark timings depend on hardware/cache/etc.
-->

| Implementation | Docs R@5 | Code R@5 |    Index | Search (199) |
| -------------- | -------: | -------: | -------: | -----------: |
| Mine           |    0.820 |    0.778 |   3.080s |       4.292s |
| Reference      |    0.850 |    0.778 | 104.535s |      65.400s |
| Required       |    0.800 |    0.500 |     300s |          90s |

<!--
OPTIONAL:
benchmark.png / bar chart

But honestly the table may already be enough.
Don't add a chart merely because blogs are "supposed" to have charts.
-->

## What about the actual RAG part?

<!--
~150-250 words

You've spent most of the article on search deliberately.

Now briefly explain:
- retrieve top-k source chunks
- fit them into bounded prompt/context
- local Qwen3-0.6B generates answer
- answer is grounded in supplied evidence

Point:
Once retrieval works, this part is comparatively straightforward.

DO NOT write a Qwen/model review.
AI isn't the focus of your site or even necessarily this article.
-->

## What I'd change

<!--
~200-350 words

This is YOUR opinions, not documentation.

Possible topics IF TRUE:

- lexical retrieval has limits when question and source share no useful words
- experiment with hybrid embedding + FTS retrieval
- better reranking
- benchmark each enrichment/reranking heuristic separately
- any architecture you now think was overkill
- parts you built mainly because they were fun
- things you'd simplify on a second attempt

This section is where your personality should show the most.
-->

## That's it

<!--
~100-150 words

Don't "In conclusion..." it.

Say what YOU found interesting.

Something roughly along the thought:

This started as a RAG project, but the parts I enjoyed were mostly ordinary
systems/search problems: parsing source correctly, designing retrieval,
making SQLite fast, handling concurrency, and keeping exact ranges correct.

Then repo link.
-->

The code is on [GitHub](https://github.com/0xveya/42-rag-against-the-machine).
