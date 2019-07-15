trait FieldImplementation {}

enum TweetNaCl {}
impl FieldImplementation for TweetNaCl {}

enum AssemblyHaase {}
impl FieldImplementation for AssemblyHaase {}

trait Field<FI: FieldImplementation {

}

pub struct FieldElement(FieldElementBuffer);





trait Curve<FieldElement: FieldImplementation> {
    type CurveCoordinates = [FieldElement; 4];
    pub struct CurvePoint(CurveCoordinates);
}

/// Since elliptic curve points are an abelian group,
/// we have a bunch of associated operations :)
#[derive(Clone,Debug)]
pub struct CurvePoint(CurveCoordinates);

type PackedPoint = [u8; 32];

