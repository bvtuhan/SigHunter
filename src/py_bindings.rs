use memflow::prelude::v1::*;
use pyo3::prelude::*;

#[pymodule]
fn sighunter_lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_os_py, m)?)?;
    m.add_class::<PyOs>()?;
    Ok(())
}

#[allow(dead_code)]
#[pyclass(name = "Os")]
pub struct PyOs {
    instance: OsInstanceArcBox<'static>,
}

#[pyfunction]
pub fn init_os_py() -> PyResult<PyOs> {
    let os = super::init_os()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{e}")))?;

    Ok(PyOs { instance: os })
}
