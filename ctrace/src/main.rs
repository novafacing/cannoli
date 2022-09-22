use cannoli::create_cannoli;
use cantracer::CanTracer;
use object::File;
use object::{Object, ObjectSection};
use std::fs::read;
use std::sync::Arc;
use yaxpeax_arch::Decoder;
use yaxpeax_x86::long_mode::InstDecoder;

fn main() {
    create_cannoli::<CanTracer>(2).unwrap();
}
