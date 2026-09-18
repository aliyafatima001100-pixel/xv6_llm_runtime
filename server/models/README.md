# Model checkpoints

This directory is **empty on purpose**. The three checkpoints the weight server
serves are not distributed with the tree: `stories110M.bin` alone is 418 MiB, past
GitHub's 100 MB per-file limit, and together they are 495 MB against 18 MB for
everything else.

Fetch them once, from the repo root:

```sh
./fetch-models.sh            # downloads all three, verifies size + SHA-256
./fetch-models.sh --check    # re-verify later, download nothing
```

| id | file | bytes |
|---|---|---|
| 1 | `stories15M.bin` | 60,816,028 |
| 2 | `tokenizer.bin` | 433,869 |
| 3 | `stories110M.bin` | 438,381,596 |

Ids 1 and 2 are required: `server/server.py` will not start without them. Id 3 is
needed by `distinf_sim.py --model 3` and by `weightfetch_regression_test.py`, which
skips its entire file when the checkpoint is absent.
