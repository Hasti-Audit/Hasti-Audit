# Hasti AI Audit — Reference Run 01
## Potential Unsafe PyTorch Checkpoint Deserialization

- Repository: https://github.com/ultralytics/ultralytics
- Commit: `eac9491607fd1ea7fe32d43e734e1c22924dc9e3`
- Review type: Static source review
- Status: Needs Security Review
- Confirmed vulnerability: No

### Evidence

1. `ultralytics/utils/__init__.py:81`
   `SAFE_LOAD = env_bool("ULTRALYTICS_SAFE_LOAD")`

2. `ultralytics/nn/tasks.py:1896-1899`
   If `safe_only` is omitted, it defaults to `SAFE_LOAD`. If restricted loading
   is unsupported, the code disables that mode.

3. `ultralytics/nn/tasks.py:1922-1925`
   Restricted mode calls `torch_load(..., weights_only=True)`. The normal path
   calls `torch_load(file, map_location="cpu")` without explicitly setting
   `weights_only=True`.

4. `ultralytics/utils/patches.py:214-219`
   When `TORCH_1_13` is true and `weights_only` is absent, the wrapper sets
   `weights_only=False` before calling `torch.load`.

5. `ultralytics/engine/model.py:252-253` and
   `ultralytics/nn/tasks.py:2033-2035`
   The `.pt` model-loading path reaches `load_checkpoint()` and then
   `torch_safe_load()`.

6. `ultralytics/nn/tasks.py:1993-2004`
   After a `ModuleNotFoundError`, when restricted mode is off, the code may
   install a missing module and retry loading through `torch_load()` without
   an explicit `weights_only=True`.

### Security interpretation

PyTorch checkpoint deserialization using `weights_only=False` can be dangerous
when the checkpoint is untrusted. The reviewed code establishes a potentially
unsafe loading path, but does not by itself establish attacker control of the
input, exploitability in a deployed context, or a confirmed vulnerability.

### Recommended follow-up

- Trace how user-supplied or remotely obtained checkpoint files reach these
  loading functions.
- Determine the trust boundary for local paths, URLs, and downloaded assets.
- Verify the exact PyTorch version and runtime behavior.
- Do not label this finding a confirmed vulnerability until exploitability and
  input control are demonstrated.

### Scan limitations

This is a static review of the specified repository revision. No malicious
checkpoint was created or loaded. No runtime exploit test was performed.
