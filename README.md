![image.png](Halo2%2028b4a288a3be80418e5fc9919aae4ce1/image.png)

## 1. What is Halo2

> ***Halo2: Trusted Setup이 필요 없는 PLONK 기반의 재귀 증명 시스템***
> 

**Halo2**는 Zcash를 개발한 Electric Coin Company(ECC)에서 설계한 최첨단 **영지식 증명(Zero-Knowledge Proof, ZKP) 시스템**이다. 이 시스템은 기존 zk-SNARKs의 한계를 극복하고 블록체인 환경에서 높은 확장성을 달성하는 것을 목표로 한다.

Halo2는 증명 구조의 핵심으로 효율성과 유연성이 높은 **PLONK 다항식 IOP(Polynomial IOP)**를 채택했다. 하지만 Halo2의 가장 큰 혁신은 보안과 효율성 두 가지 측면에서 나타납니다.

- **신뢰할 수 있는 설정(Trusted Setup) 제거**
    
    많은 초기 zk-SNARK 시스템은 증명 시스템을 초기화하기 위해 비밀 키('독성 폐기물')가 생성되는 **Trusted Setup** 과정을 필요로 했다. Halo2는 이러한 과정을 **완전히 제거**하여, 설정 과정의 보안 위험 없이 누구나 투명하고 안전하게 사용할 수 있는 **Trustless 시스템**을 구현했다.
    
- **재귀적 증명의 효율성 극대화**
    
    zk-proof 시스템에서 확장성을 확보하기 위해 **재귀적 증명(Recursive Proofs)**, 즉 '증명의 증명'을 통해 수많은 연산 증명들을 하나의 간결한 최종 증명으로 **집계(Aggregate)**하는 것이 중요하다. 그러나 이 과정에서 검증 회로 내부에 타원 곡선 페어링 연산(G 연산)을 인코딩해야 했기 때문에 증명자(Prover)의 계산 부담이 비효율적으로 커지는 문제가 있었다.
    
    Halo2는 **Nested Amortization**이라는 혁신적인 **증명 집계(Accumulation Scheme)** 기술을 도입하여 이 비효율을 해결했다. 이 기술은 검증 회로 내에서 비용이 큰 타원 곡선 연산을 직접 수행하는 것을 피하고, 대신 새로운 증명을 생성할 때 이전 증명의 검증 결과를 효율적으로 **축적**하게 한다.
    

이러한 방식으로 Halo2는 증명 생성 시간을 획기적으로 단축하고 재귀적 증명의 효율성을 극대화함으로써, ZK-Rollups와 같은 대규모 분산 시스템의 **확장성 문제를 실질적으로 해결**하는 데 기여하고 있다.

## 2. Implementing zk-SNARK Circuits with Halo2

### 전체 구조 흐름

<aside>
✒️

**Config 정의 → Chip 구조체로 감싸기 → Trait로 연산 게이트 정의 → Layouter로 값을 할당 → Circuit으로 synthesize → Prove**

</aside>

- Config : 어떤 열들(column)이 필요한지 정의
- Chip : 계산 단위의 회로 기능 묶음
- Trait : 실제 계산 정의(gate 정의)
- Layouter : 회로의 실제 layout과 값 할당 방식 정의
- Circuit : 회로 전체를 synthesize로 연결하고 구성
- MockProver : 실제 증명 시뮬레이션 도구

### a. Config : 회로의 '부품' 정의

영지식 증명(zk-SNARK) 시스템에서는 증명하고자 하는 statement가 만족해야 하는 constraint를 *를 기준으로 쪼개고 정의한다. 예를 들어 `out = x^3 + x + 5` 를 증명하려고 할 때, 이 식을 평탄화하여 다음과 같이 나타낸다.

```
sym_1 = x * x

y = sym_1 * x

sym_2 = y + x

~out = sym_2 + 5
```

그리고 이걸 `[1, x, ~out, sym_1, y, sym_2]` 와 같은 솔루션 벡터에 넣는다. 그렇게 되면 각 행은 계산 단계를 나타내게되고, 각 열은 변수 및 값을 저장하게 된다. 

우리가 증명하려는 statement를 증명하는 데 필요한 값들을 저장하는 것(어떤 열이 필요한지 정의)하는 단계가 바로 **Config**이다. 

각 열의 타입에 따라서 용도가 달라지는데, 자세한 내용을 다음과 같다.

| 컴포넌트 | 목적 |
| --- | --- |
| `Column<Advice>` | witness (private input, wire) (= 증명 과정 중 채워지는 값들) |
| `Column<Fixed>` | 컴파일 타임에 고정된 상수 또는 selector (게이트 활성화 여부) |
| `Column<Instance>` | 공개 입력값 |
| `Selector` | Fixed의 특수 버전으로, 특정 행(row)에만 제약조건을 활성화 |

```rust
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
```

> 🔗 왜 필요 한가?
> 
> - 증명 시스템은 **각 행에 대해 어떤 열들이 어떤 조건을 만족하는지 계산해야 하므로**, 형식을 정하고 열들을 구분해서 관리해야 함

### b. Chip : 기능 단위의 회로 패키지

**Chip**은 Halo2 회로 설계에서 **기능적 모듈화**와 **타입 안전성**을 확보하는 데 핵심적인 역할을 한다. Chip의 가장 중요한 역할은 특정 **계산 로직(게이트의 집합)**을 하나의 단위로 묶는 것이다. 

Chip은 앞서 정의한 Config와 marker를 포함한다. Config가 회로의 부품'(열, Column)을 정의했다면, Chip은 이 부품들을 사용하여 수행할 '특정 기능'을 정의하고 관리하는 주체이다. 즉, Chip을 통해서 덧셈을 담당하는 Chip, 곱셈을 담당하는 Chip, 유한체 연산을 담당하는 Chip 등, 기능별로 분리하여 설계할 수 있는 것이다. 이때문에 하나의 Chip을 여러 회로의 다른 부분에서 **재사용**할 수 있다.

PhantomData는 **메모리를 전혀 차지하지 않으면서**, 해당 구조체가 **F** 타입에 **논리적으로 의존하고 있음**을 명시하여, 컴파일러가 **F**와 관련된 모든 **타입 제약 조건을 올바르게 검사**하고 **타입 안정성**을 보장하도록 돕는다.

```rust
pub struct TestChip<F: Field> {
    pub config: TestConfig,
    pub _marker: PhantomData<F>,
}
```

지금 코드를 보면 config, marker만 정의되어 있는데 이것만으로는 chip이 어떤 기능을 수행하는지는 알 수 없다. Chip의 실제 기능은 Trait에서 정의된다.

### c. Trait: 계산(게이트) 로직을 정의

**Trait**은 Halo2에서 **Chip**이 가져야 할 기능(메소드)의 규약(Interface)을 정의한다. Trait에는 `fn add_gate(...)`, `fn mul(...)` 등의 statement를 증명하는데 필요한 모든 연산이 정의되어야 한다. 이 과정을 통해 덧셈이나 곱셈 같은 동일한 계산 기능이 여러 **Chip**에서 각기 다른 방식으로 구현되더라도, Trait이 해당 기능들의 이름과 입력/출력 형식을 **표준화**하여 **Circuit**의 `synthesize` 단계에서 **어떤 Chip을 사용하든 통일된 방식으로 연산을 호출할 수 있게** 한다.

Trait은 앞서 정의된 Chip 구조체에 실제적인 기능을 부여하는 역할을 한다고 했다. Chip 구조체(예: TestChip) 자체는 Config나 PhantomData 같은 회로의 설정과 타입 정보만 담는 데이터 컨테이너에 불과하다. 그러나 `impl Trait for Chip` 블록에서 `mul` 함수와 같은 구체적인 Trait 메소드들이 구현될 때, 해당 로직은 Layouter를 사용하여 열에 값을 할당하고 제약 조건을 활성화하는 형태로 작성된다. 즉, Trait은 Chip이 갖춰야 할 '기능 계약서'로서, 이 구현 과정을 통해 Chip은 비로소 실제 회로 로직을 수행하는 주체가 된다.

- `s( a * b - c ) = 0`

```rust
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
```

### d. Layouter: 회로에 값 할당

**Layouter**는 Halo2 회로 구현에서 **정의된 회로 구조(Config)**에 **실제 값(Witness, 상수)**을 채워 넣고 **제약 조건을 활성화**하는 역할을 수행한다. 

Layouter는 일반적으로 **`assign_region()`** 메서드를 통해 값 할당 작업을 수행하여 회로를 논리적 단위로 분할한다. `assign_region()`을 호출하면 내부적으로 **Region**이라는 개념이 생성된다. **Region**은 회로 테이블 내의 **특정 연속된 행(row) 블록**을 의미하며, 이는 보통 **하나의 논리적 작업 단위** (예: 곱셈 연산 하나)에 해당한다. **Region** 클로저 내부에서 `region.assign_advice()`, `region.assign_fixed()` 등의 메서드를 사용하여 지정된 **Advice**나 **Fixed** 열의 **특정 행**에 실제 계산 값을 할당하는 작업을 수행한다.

이렇게 **Layouter를 통해 구조에 실제 값을 채워 넣어 회로가 논리적으로 작동하도록** 만든다. **Layouter**가 정확한 **Witness** 값과 **Selector**를 배치해야만, 나중에 **MockProver**나 **Prover**가 해당 **Row**에서 s(a⋅b−c)=0과 같은 **다항식 제약 조건이 충족되는지 검증**할 수 있다.

### e. Circuit: 전체 회로 조립

**Circuit**은 Halo2에서 **zk-SNARK** 회로를 정의하고 구체화하는 **최종 단계이자 핵심 구조체**이다. **Config, Chip, Trait, Layouter** 등 앞서 정의된 모든 구성 요소를 **통합**하여, 증명 시스템이 검증할 수 있는 회로의 **정적 구조**와 **동적 작동 방식**을 모두 정의하는 역할을 수행한다.

**Circuit**은 두 가지 필수 메소드인 **configure**와 **synthesize**를 제공해야 한다.

- configure (정적 회로 구조 정의)
    - **역할:** 회로의 **정적(static) 구조와 규칙**을 정의하는 단계이며, 회로가 만들어지기 전에 **한 번만 실행**된다.
    - **주요 작업:**
        - **열(Column) 선언:** **Advice, Fixed, Instance** 열을 선언한다.
        - **동일성 활성화:** 특정 열에 대해 `enable_equality()`를 호출하여 **Cell 간의 값 동일성 제약**을 허용한다.
        - **게이트 생성:** `create_gate()`를 사용하여 회로의 핵심 제약 조건(다항식)을 정의한다. 이 게이트들은 회로의 모든 행에 영구적으로 적용되는 규칙이다.
    - 이 단계의 결과물은 **Config**이며, 이는 회로의 **뼈대와 규칙**이 된다
- synthesize (동적 회로 작동 정의)
    - **역할:** **실제 증명 생성 시** 회로에 값(Witness)이 할당되고 작동하는 **동적(dynamic) 방식**을 정의하는 단계이다.
    - **주요 작업:**
        - **Chip 초기화:** `configure`에서 정의된 **Config**를 사용하여 **Chip**을 생성한다.
        - **값 할당:** **Layouter** 객체를 인수로 받아, **Chip**에 구현된 **Trait** 함수들을 호출한다. 이 과정에서 **Layouter**를 통해 **Witness** 값(개인 입력 및 중간 결과)이 **Advice** 열에 할당되고, **Selector**가 활성화된다.
        - **공개 입력 노출:** `expose_public()`을 사용하여 회로 내부의 값이 **Instance** 열(공개 입력)과 연결되도록 제약을 건다.
    - 이 단계의 결과물은 **Layouter**를 통한 **완성된 값 배치**이며, 이는 **MockProver**나 **Prover**가 증명을 생성할 때 사용되는 **실제 작동 방식**이 된다.

```rust
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
        chip.constrain_equal(layouter.namespace(|| "eq"), out, c_loaded.clone())?;
        chip.expose_public(layouter.namespace(|| "expose c"), c_loaded, 0)
    }
}
```

### f. Proof & MockProver: 동작 확인 or 실제 증명

앞서 **Circuit**을 통해 정의되고 값이 할당된 회로가 **수학적 제약 조건(Constraints)을 실제로 만족하는지 확인**하고, 최종적으로 **zk-SNARK 증명을 생성**하는 과정이다. 이 단계는 **테스트 환경**과 **실제 운영 환경**으로 나뉜다.

- **MockProver: 로컬 테스트 및 제약 조건 확인**
    
    **MockProver**는 개발 과정에서 **로컬 테스트를 위해 사용되는 도구**이다. 실제 암호학적 증명 생성 과정을 거치지 않고, **회로 내의 모든 제약 조건이 수학적으로 만족되었는지** 빠르게 검사한다.
    
    **실행 과정:**
    
    1. **k 값 설정:** `let prover = MockProver::run(k, ...)`에서 k 값을 설정한다. **k**는 회로가 사용할 수 있는 최대 행(row)의 개수를 결정하는 매개변수로, **$2^{\text{k}}$보다 작은 수의 행**을 사용해야 함을 의미한다. 즉, k **는 회로의 크기**를 정의한다.
    2. **입력 준비:** `vec![...]` 부분은 공개 입력값(Public Inputs)을 벡터 형태로 준비하여 prover에 전달한다.
    3. **실행 및 확인:** `MockProver::run()`으로 회로를 실행한 후, `.assert_satisfied()` 메소드를 호출하여 **모든 제약 조건이 0이 되어 충족되었는지 확인**한다. 만족하지 않으면 오류(Error)를 반환한다.
- **Prover: 실제 증명 생성**
    
    **Prover**는 **MockProver**를 통한 테스트가 완료된 후, **실제 운영 환경에서 영지식 증명을 생성**하는 데 사용되는 주체이다.
    
    `synthesize` 단계에서 **Layouter**에 의해 채워진 열(Column)의 값을 기반으로 다항식 연산을 수행하고, **Halo2의 복잡한 암호학적 프로토콜**을 적용하여 최종 증명 파일을 산출한다.
    

```rust
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
```

## 3. Finalization

**a*b=c를 증명하는 circuit 구현**

```rust
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
        chip.constrain_equal(layouter.namespace(|| "eq"), out, c_loaded.clone())?;
        chip.expose_public(layouter.namespace(|| "expose c"), c_loaded, 0)
    }
}

fn main() {}

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

```

**결과**

![image.png](Halo2%2028b4a288a3be80418e5fc9919aae4ce1/image%201.png)