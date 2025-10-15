use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};
use halo2_proofs::poly::Rotation;
use halo2_proofs::pasta::Fp;
use ff::Field;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
//Circuit Config
pub struct TestConfig {
    // a*b=c를 증명하고 싶음
    // 즉, s(a*b-c) = 0 이라는 걸 만들어서 증명
    
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,

    pub s: Column<Fixed>,
    pub instance: Column<Instance>,
}
//Chip
pub struct TestChip<F: Field> {
    pub config: TestConfig,
    pub _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for TestChip<F> {
    type Config = TestConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config { &self.config }
    fn loaded(&self) -> &Self::Loaded { &() }
}

//trait
trait TestComposer<F: Field>: Chip<F> {
    type Var;

    fn load_private(&self, layouter: impl Layouter<F>, v: Value<F>) -> Result<Self::Var, Error>;

    fn mul(&self, layouter: impl Layouter<F>, a: Self::Var, b: Self::Var)
      -> Result<Self::Var, Error>; // 내부에서 s=1, a/b/c 배치
  
    fn constrain_equal(&self, layouter: impl Layouter<F>, x: Self::Var, y: Self::Var)
      -> Result<(), Error>;
  
    fn expose_public(&self, layouter: impl Layouter<F>, v: Self::Var, row: usize)
      -> Result<(), Error>;
}

// trait 구현 
impl<F: Field> TestChip<F> {
    pub fn new(config: TestConfig) -> Self { Self { config, _marker: PhantomData } }
}

impl<F: Field> TestComposer<F> for TestChip<F> {
    type Var = AssignedCell<F, F>;

    fn load_private(&self, mut layouter: impl Layouter<F>, v: Value<F>) -> Result<Self::Var, Error> {
        let cfg = &self.config;
        layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "w", cfg.a, 0, || v),
        )
    }

    fn mul(&self, mut layouter: impl Layouter<F>, a: Self::Var, b: Self::Var) -> Result<Self::Var, Error> {
        let cfg = &self.config;
        layouter.assign_region(
            || "mul",
            |mut region| {
                // s=1, 같은 행에 a,b 복사 후 c=a*b 할당
                region.assign_fixed(|| "s", cfg.s, 0, || Value::known(F::ONE))?;
                a.copy_advice(|| "a", &mut region, cfg.a, 0)?;
                b.copy_advice(|| "b", &mut region, cfg.b, 0)?;
                let val = a.value().copied() * b.value();
                region.assign_advice(|| "c", cfg.c, 0, || val)
            },
        )
    }

    fn constrain_equal(&self, mut layouter: impl Layouter<F>, x: Self::Var, y: Self::Var) -> Result<(), Error> {
        layouter.assign_region(
            || "constrain equal",
            |mut region| {
                region.constrain_equal(x.cell(), y.cell())
            }
        )
    }

    fn expose_public(&self, mut layouter: impl Layouter<F>, v: Self::Var, row: usize) -> Result<(), Error> {
        let cfg = &self.config;
        layouter.constrain_instance(v.cell(), cfg.instance, row)
    }
}

// circuit 정의 (기존 이름 유지)
#[derive(Default)]
pub struct TestCircuit<F: Field> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        let s = meta.fixed_column();
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        meta.create_gate("a*b=c", |meta| {
            let aq = meta.query_advice(a, Rotation::cur());
            let bq = meta.query_advice(b, Rotation::cur());
            let cq = meta.query_advice(c, Rotation::cur());
            let sq = meta.query_fixed(s);
            vec![sq * (aq * bq - cq)]
        });

        TestConfig { a, b, c, s, instance }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let chip = TestChip::<F>::new(config);
        let a = chip.load_private(layouter.namespace(|| "a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "b"), self.b)?;
        let out = chip.mul(layouter.namespace(|| "mul"), a, b)?;
        // c를 로드하고 out==c를 강제
        let c_loaded = layouter.assign_region(
            || "load c",
            |mut region| region.assign_advice(|| "c", chip.config.c, 0, || self.c),
        )?;
        chip.constrain_equal(layouter.namespace(|| "eq"), out, c_loaded)?;
        chip.expose_public(layouter.namespace(|| "expose c"), c_loaded, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ab_mul_c_succeeds() {
        let k = 4u32;
        let a = Fp::from(3);
        let b = Fp::from(4);
        let c = a * b;
        let circuit = TestCircuit { a: Value::known(a), b: Value::known(b), c: Value::known(c) };
        let prover = MockProver::run(k, &circuit, vec![vec![c]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_ab_mul_c_fails() {
        let k = 4u32;
        let a = Fp::from(3);
        let b = Fp::from(4);
        let wrong_c = a * b + Fp::one();
        let circuit = TestCircuit { a: Value::known(a), b: Value::known(b), c: Value::known(a * b) };
        let prover = MockProver::run(k, &circuit, vec![vec![wrong_c]]).unwrap();
        assert!(prover.verify().is_err());
    }
}


