# Gadget Protocol Template

This repository serves as a template to start hacking on a new distributed system, MPC protocol, or other offchain computation system using Tangle's gadget framework. This template contains a `StubProtocol` which simply sets up the boilerplate necessary for a new protocol. Please refer to the [gadget repo](https://github.com/webb-tools/gadget) for example protocols and more information on how to use the gadget framework, especially if you'd like to help improve the gadget framework.

## Getting Started
### Preqrequisits
First install and configure `rustup`:

```bash
# Install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Configure
source ~/.cargo/env
```
### Execution
1. To build the project, run:
```bash
RUSTFLAGS="--cfg tokio_unstable" cargo b -r
```
2. To test the project, run:
```bash
RUSTFLAGS="--cfg tokio_unstable" cargo t -r
```

# Creating a new protocol

#### Step 1: Add `gadget-common`, `async-trait`, `protocol-macros`, `tangle-primitives`, and `tokio` as a dependencies
```toml
gadget-common = { workspace = true }
async-trait = { workspace = true }
tokio = { workspace = true }
tangle-primitives = { workspace = true }
protocol-macros = { workspace = true }
```

#### Step 2: Create a struct representing the protocol as such:
```rust
#[protocol]
pub struct StubProtocol<
    B: Block,
    BE: Backend<B> + 'static,
    C: ClientWithApi<B, BE>,
    N: Network,
    KBE: KeystoreBackend,
> where
        <C as ProvideRuntimeApi<B>>::Api: JobsApiForGadget<B>,
{
    pallet_tx: Arc<dyn PalletSubmitter>,
    logger: DebugLogger,
    client: C,
    network: N,
    account_id: AccountId,
    key_store: ECDSAKeyStore<KBE>,
    jobs_client: Arc<Mutex<Option<JobsClient<B, BE, C>>>>,
}
```

#### Step 2: Implement `FullProtocolConfig` for `StubProtocol`

#### Step 3: Running the protocol
At the bottom of lib.rs, add the macro: `generate_setup_and_run_command!(StubProtocol, StubProtocol, ...)`. For real applications, you will want to add all the protocol configs you wish to run concurrently.

#### Step 4: Testing the protocol:
After generating the macro above, run this macro with appropriate `T`, `N`, and `K` values: `test_utils::generate_signing_and_keygen_tss_tests!(T, N, K, ThresholdSignatureRoleType::StubProtocol)`. Note: the `K` value is the number of expected protocols to run concurrently. It should match the number of items in the `generate_setup_and_run_command!` macro. 
