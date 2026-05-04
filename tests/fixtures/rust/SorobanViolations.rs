#![no_std]
//! Synthetic Soroban-shaped source for analyzer tests (syntax not compiled here).

pub struct Demo;

#[contractimpl]
impl Demo {
    pub fn mutate_without_auth(env: Env, amount: Vec<i128>) {
        env.storage().instance().set(&KEY_FEE, &amount);
        env.invoke_contract(&X, &Y, ());
        assert!(amount.len() > 0);
        for _marker in STATIC_ITER {
            let _ = env.storage().persistent().get(&KEY_FEE);
        }
    }

    pub fn guarded(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&OWNER, &1);
        env.storage().persistent().extend_ttl(&OWNER, 10000, 20000);
        env.try_invoke_contract(&EXTERNAL, &SYMBOL, args);
        panic_with_error!(&env, Error::Abort);
        normal_call();
    }

    pub fn __constructor(env: Env, root: Address) {
        env.storage().instance().set(&OWNER, &root);
    }
}
