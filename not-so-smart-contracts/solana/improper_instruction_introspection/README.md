# Improper Instruction Introspection

Solana allows programs to inspect other instructions in the transaction using the [Instructions sysvar](https://docs.solanalabs.com/implemented-proposals/instruction_introspection). The programs requiring instruction introspection divide an operation into two or more instructions. The program have to ensure that all the instructions related to an operation are correlated. The program could access the instructions using absolute indexes or relative indexes. Using relative indexes ensures that the instructions are implicitly correlated. The programs using absolute indexes might become vulnerable to exploits if additional validations to ensure the correlation between instructions are not performed.

## Exploit Scenario

A program mints tokens based on the amount of tokens transferred to it. A program checks that `Token::transfer` instruction is called in the first instruction of the transaction. The program uses absolute index `0` to access the instruction data, program id and validates them. If the first instruction is a `Token::transfer` then program mints some tokens.

```rust
pub fn mint(
    ctx: Context<Mint>,
    // ...
) -> Result<(), ProgramError> {
    // [...]
    let transfer_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
        0usize,
        ctx.instructions_account.to_account_info(),
    )?;

    if transfer_ix.program_id != spl_token::id() {
        return Err(ProgramError::InvalidInstructionData);
    }
    // check transfer_ix transfers
    // mint to the user account
    // [...]
    Ok(())
}
```

The program uses absolute index to access the transfer instruction. An attacker can create transaction containing multiple calls to `mint` and single transfer instruction.

0. `transfer()`
1. `mint(, ...)`
2. `mint(, ...)`
3. `mint(, ...)`
4. `mint(, ...)`
5. `mint(, ...)`

All the `mint` instructions verify the same transfer instruction. The attacker gets 4 times more than the intended tokens.

## Mitigation

Use a relative index, for example `-1`, and ensure the instruction at that offset is the `transfer` instruction.

```rust
pub fn mint(
    ctx: Context<Mint>,
    // ...
) -> Result<(), ProgramError> {
    // [...]
    let transfer_ix = solana_program::sysvar::instructions::get_instruction_relative(
        -1i64,
        ctx.instructions_account.to_account_info(),
    )?;
    // [...]
}
```

Let's say you have a simple "Swap" program that:

- Takes in user's SOL
- Mints them tokens in return
- Needs to verify the SOL transfer happened

```rust
// Vulnerable pattern
pub fn process_swap(ctx: Context<Swap>) -> Result<()> {
    // Checks instruction at index 0 is a SOL transfer
    let transfer_ix = solana_program::sysvar::instructions::load_instruction_at_checked(
        0, // BAD: Absolute index
        &ctx.accounts.instructions
    )?;

    if verify_sol_transfer(&transfer_ix) {
        // Mint tokens to user...
    }
}
```

A user could create a transaction like:

- Transfer SOL
- Swap
- Swap again (reuses same transfer verification)
- Swap again (reuses same transfer verification)

B) To detect this:

Grep for these specific imports/uses:

```rust
solana_program::sysvar::instructions
sysvar::instructions
Instructions::load
load_instruction_at
```

Look for patterns where code needs to verify "X happened before Y":
Comments mentioning "must be called after"
Functions that check token transfers
Code that looks at transaction history


Look for these account types in struct definitions:

```rust
sysvar::instructions::Instructions
```

The key is: anytime a program needs to verify "some other instruction happened", it needs to use relative instruction indexing or could be vulnerable.
