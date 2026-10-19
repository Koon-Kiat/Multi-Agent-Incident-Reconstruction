# Private runbooks

Place Dataset & Ground Truth Management's original scenario execution runbooks under `runbooks/private/` (ignored by Git). Keep the VM
steps, scenario time windows, actual actions and original record references alongside the private key.
This public folder does not supply those files. See [`ground_truth/README.md`](../ground_truth/README.md).

Runbooks are independent validation material. Investigation agents, reconstruction and verification must
not read them or use them to select evidence. Do not generate retrospective runbooks from model output.
