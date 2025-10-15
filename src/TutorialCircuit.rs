use std::marker::PhantomData;
use halo2_proofs::circuit::{Cell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};
use halo2_proofs::poly::Rotation;
use ff::Field;

#[derive(Clone, Debug)]
pub struct TutorialConfig {
	pub l: Column<Advice>,
	pub r: Column<Advice>,
	pub o: Column<Advice>,

	pub sl: Column<Fixed>,
	pub sr: Column<Fixed>,
	pub sm: Column<Fixed>,
	pub so: Column<Fixed>,
	pub sc: Column<Fixed>,
	pub pi: Column<Instance>,
}

pub struct TutorialChip<F: Field> {
	pub config: TutorialConfig,
	pub _marker: PhantomData<F>,
}

impl<F: Field> TutorialChip<F> {
	pub fn new(config: TutorialConfig) -> Self {
		Self { config, _marker: PhantomData }
	}
}

pub trait TutorialComposer<F: Field>: Chip<F> {
	fn raw_add<FM>(
		&self,
		layouter: &mut impl Layouter<F>,
		f: FM,
	) -> Result<(Cell, Cell, Cell), Error>
	where
		FM: FnMut() -> Value<(Assigned<F>, Assigned<F>, Assigned<F>)>;

	fn raw_multiply<FM>(
		&self,
		layouter: &mut impl Layouter<F>,
		f: FM,
	) -> Result<(Cell, Cell, Cell), Error>
	where
		FM: FnMut() -> Value<(Assigned<F>, Assigned<F>, Assigned<F>)>;

	fn copy(
		&self,
		layouter: &mut impl Layouter<F>,
		src: Cell,
		dst_col: Column<Advice>,
		row: usize,
	) -> Result<Cell, Error>;

	fn expose_public(
		&self,
		layouter: &mut impl Layouter<F>,
		cell: Cell,
		instance_row: usize,
	) -> Result<(), Error>;
}

impl<F: Field> TutorialChip<F> {
	pub fn raw_add<FM>(
		&self,
		layouter: &mut impl Layouter<F>,
		mut f: FM,
	) -> Result<(Cell, Cell, Cell), Error>
	where
		FM: FnMut() -> Value<(Assigned<F>, Assigned<F>, Assigned<F>)>,
	{
		layouter.assign_region(
			|| "add",
			|mut region| {
				let mut values: Option<Value<(Assigned<F>, Assigned<F>, Assigned<F>)>> = None;
				let lhs = region.assign_advice(
					|| "lhs",
					self.config.l,
					0,
					|| {
						values = Some(f());
						values.as_ref().unwrap().map(|v| v.0)
					},
				)?;
				let rhs = region.assign_advice(
					|| "rhs",
					self.config.r,
					0,
					|| values.as_ref().unwrap().map(|v| v.1),
				)?;
				let out = region.assign_advice(
					|| "out",
					self.config.o,
					0,
					|| values.as_ref().unwrap().map(|v| v.2),
				)?;

				region.assign_fixed(|| "m", self.config.sm, 0, || Value::known(F::ONE))?;
				region.assign_fixed(|| "o", self.config.so, 0, || Value::known(F::ONE))?;

				Ok((lhs.cell(), rhs.cell(), out.cell()))
			},
		)
	}

	pub fn raw_multiply<FM>(
		&self,
		layouter: &mut impl Layouter<F>,
		mut f: FM,
	) -> Result<(Cell, Cell, Cell), Error>
	where
		FM: FnMut() -> Value<(Assigned<F>, Assigned<F>, Assigned<F>)>,
	{
		layouter.assign_region(
			|| "mul",
			|mut region| {
				let mut values: Option<Value<(Assigned<F>, Assigned<F>, Assigned<F>)>> = None;
				let lhs = region.assign_advice(
					|| "lhs",
					self.config.l,
					0,
					|| {
						values = Some(f());
						values.as_ref().unwrap().map(|v| v.0)
					},
				)?;
				let rhs = region.assign_advice(
					|| "rhs",
					self.config.r,
					0,
					|| values.as_ref().unwrap().map(|v| v.1),
				)?;
				let out = region.assign_advice(
					|| "out",
					self.config.o,
					0,
					|| values.as_ref().unwrap().map(|v| v.2),
				)?;

				region.assign_fixed(|| "m", self.config.sm, 0, || Value::known(F::ONE))?;
				region.assign_fixed(|| "o", self.config.so, 0, || Value::known(F::ONE))?;

				Ok((lhs.cell(), rhs.cell(), out.cell()))
			},
		)
	}
	pub fn copy(
		&self,
		layouter: &mut impl Layouter<F>,
		src: Cell,
		dst_col: Column<Advice>,
		row: usize,
	) -> Result<Cell, Error>{
		// Copy as: constrain equality between an existing cell and a newly assigned one
		layouter.assign_region(
			|| "copy",
			|mut region| {
				let copied = region.assign_advice(|| "copy dst", dst_col, row, || Value::<F>::unknown())?;
				region.constrain_equal(src, copied.cell())?;
				Ok(copied.cell())
			},
		)
	}
	pub fn expose_public(
		&self,
		layouter: &mut impl Layouter<F>,
		cell: Cell,
		instance_row: usize,
	) -> Result<(), Error>{
		layouter.constrain_instance(cell, self.config.pi, instance_row)
	}
}

pub struct TutorialCircuit<F: Field> {
	x : Value<F>,
	y : Value<F>,
	constant : F,
}

impl<F: Field> Circuit<F> for TutorialCircuit<F> {
    type Config = TutorialConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { x: Value::unknown(), y: Value::unknown(), constant: F::ONE }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let l = meta.advice_column();
        let r = meta.advice_column();
        let o = meta.advice_column();

        meta.enable_equality(l);
        meta.enable_equality(r);
        meta.enable_equality(o);

        let sm = meta.fixed_column();
        let sl = meta.fixed_column();
        let sr = meta.fixed_column();
        let so = meta.fixed_column();
        let sc = meta.fixed_column();
        let pi = meta.instance_column();
        meta.enable_equality(pi);

        meta.create_gate("mini plonk", |meta| {
            let lq = meta.query_advice(l, Rotation::cur());
            let rq = meta.query_advice(r, Rotation::cur());
            let oq = meta.query_advice(o, Rotation::cur());

        let slq = meta.query_fixed(sl);
        let srq = meta.query_fixed(sr);
        let soq = meta.query_fixed(so);
        let smq = meta.query_fixed(sm);
        let scq = meta.query_fixed(sc);

            vec![lq.clone() * slq + rq.clone() * srq + lq * rq * smq + (oq * soq * (-F::ONE)) + scq]
        });

        TutorialConfig { l, r, o, sl, sr, sm, so, sc, pi }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cs: TutorialChip<F> = TutorialChip::new(config);

        let x = self.x;
        let y = self.y;
        let z = x * y;

        let (_l, _r, out) = cs.raw_multiply(&mut layouter, || {
            x.zip(y).zip(z).map(|((xv, yv), zv)| (Assigned::from(xv), Assigned::from(yv), Assigned::from(zv)))
        })?;

        cs.expose_public(&mut layouter, out, 0)?;
        Ok(())
    }
}

fn main() {
	use halo2_proofs::dev::MockProver;
	use halo2_proofs::pasta::Fp;

	let k = 4u32;
	let a = Fp::from(3);
	let b = Fp::from(4);
	let c = a * b;

	let circuit: TutorialCircuit<Fp> = TutorialCircuit {
		x: Value::known(a),
		y: Value::known(b),
		constant: Fp::one(),
	};

	let public_inputs = vec![c];
	let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
	assert_eq!(prover.verify(), Ok(()));

	let wrong = vec![c + Fp::one()];
	let prover = MockProver::run(k, &circuit, vec![wrong]).unwrap();
	assert!(prover.verify().is_err());
}

// removed outdated tests referencing MyCircuit