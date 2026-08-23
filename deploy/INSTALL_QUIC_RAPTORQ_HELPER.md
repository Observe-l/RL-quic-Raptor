# Installing the optional QUIC-FEC network helper

The helper is opt-in. If `QUIC_FEC_PRIV_HELPER` is unset, the existing
`sudo`-based experiment path is unchanged.

## Install once

From the repository root, run these commands as the normal experiment user:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec

sudo install -o root -g root -m 0755 \
  scripts/quicfec_net_helper.sh \
  /usr/local/libexec/quicfec-net-helper

sed "s/^YOUR_USER /$(id -un) /" \
  deploy/quic-raptorq-sudoers.example | \
  sudo tee /etc/sudoers.d/quic-raptorq >/dev/null

sudo chmod 0440 /etc/sudoers.d/quic-raptorq
sudo visudo -cf /etc/sudoers.d/quic-raptorq
sudo -n /usr/local/libexec/quicfec-net-helper self-test
```

The last command must print `ok`.

## Enable for an experiment

```bash
export QUIC_FEC_PRIV_HELPER=/usr/local/libexec/quicfec-net-helper
python3 python/experiments/test_bandit_model_ge_steady_rp.py \
  --model-prefix python/results/ge-128k-bandit-model/bandit_model \
  --sender-id 28 \
  --ge-key GE_steady_rp \
  --reps 1
```

The helper runs `quicfec-server` inside the isolated namespace using the same
privilege level as the original experiment path, then returns generated
`.recv`/`.part` artifacts to the invoking user. It only performs the
namespace, veth, `tc`, UDP-buffer, and namespace-server operations that the
experiment needs. It does not accept an arbitrary shell command.

The `cleanup` subcommand removes one experiment namespace and its host veth:

```bash
sudo -n /usr/local/libexec/quicfec-net-helper cleanup qns veth0
```

If the helper source is changed later, reinstall the root-owned copy before
using the new version:

```bash
sudo install -o root -g root -m 0755 \
  scripts/quicfec_net_helper.sh \
  /usr/local/libexec/quicfec-net-helper
```
