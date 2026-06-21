// CPython binding for the optisocks5 sans-IO SOCKS5 codec -> optisocks5._core.
//
// Exposes the pure byte builders/parsers; all I/O (sockets, event loop) stays
// in Python. See ../src/optisocks5/__init__.py for the user-facing API.
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "socks5_codec.hpp"

namespace {

PyObject* bytes_from(const std::vector<std::uint8_t>& v) {
  return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(v.data()),
                                   static_cast<Py_ssize_t>(v.size()));
}

std::span<const std::uint8_t> as_span(const char* buf, Py_ssize_t len) {
  return {reinterpret_cast<const std::uint8_t*>(buf),
          static_cast<std::size_t>(len)};
}

// ---- TCP control channel ---------------------------------------------------

PyObject* py_client_greeting(PyObject*, PyObject* args) {
  const char* methods;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &methods, &len)) return nullptr;
  return bytes_from(s5::client_greeting(as_span(methods, len)));
}

PyObject* py_parse_method_selection(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto m = s5::parse_method_selection(as_span(buf, len));
  if (!m) Py_RETURN_NONE;
  return PyLong_FromLong(*m);
}

PyObject* py_userpass_auth(PyObject*, PyObject* args) {
  const char* user;
  Py_ssize_t ulen;
  const char* pass;
  Py_ssize_t plen;
  if (!PyArg_ParseTuple(args, "s#s#", &user, &ulen, &pass, &plen))
    return nullptr;
  return bytes_from(s5::userpass_auth(std::string_view(user, ulen),
                                      std::string_view(pass, plen)));
}

PyObject* py_parse_auth_reply(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto s = s5::parse_auth_reply(as_span(buf, len));
  if (!s) Py_RETURN_NONE;
  return PyLong_FromLong(*s);
}

PyObject* py_request(PyObject*, PyObject* args) {
  int cmd;
  const char* host;
  int port;
  if (!PyArg_ParseTuple(args, "isi", &cmd, &host, &port)) return nullptr;
  s5::Address dst{host, static_cast<std::uint16_t>(port)};
  return bytes_from(s5::request(static_cast<std::uint8_t>(cmd), dst));
}

PyObject* py_parse_reply(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto r = s5::parse_reply(as_span(buf, len));
  if (!r) Py_RETURN_NONE;
  return Py_BuildValue("(isi)", static_cast<int>(r->rep), r->bound.host.c_str(),
                       static_cast<int>(r->bound.port));
}

// ---- TCP control channel, SERVER side --------------------------------------

PyObject* py_parse_greeting(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto m = s5::parse_greeting(as_span(buf, len));
  if (!m) Py_RETURN_NONE;
  return bytes_from(*m);
}

PyObject* py_method_selection(PyObject*, PyObject* args) {
  int method;
  if (!PyArg_ParseTuple(args, "i", &method)) return nullptr;
  return bytes_from(s5::method_selection(static_cast<std::uint8_t>(method)));
}

PyObject* py_parse_userpass(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto up = s5::parse_userpass(as_span(buf, len));
  if (!up) Py_RETURN_NONE;
  return Py_BuildValue("(ss)", up->user.c_str(), up->pass.c_str());
}

PyObject* py_auth_reply(PyObject*, PyObject* args) {
  int status;
  if (!PyArg_ParseTuple(args, "i", &status)) return nullptr;
  return bytes_from(s5::auth_reply(static_cast<std::uint8_t>(status)));
}

PyObject* py_parse_request(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto req = s5::parse_request(as_span(buf, len));
  if (!req) Py_RETURN_NONE;
  return Py_BuildValue("(isi)", static_cast<int>(req->cmd), req->dst.host.c_str(),
                       static_cast<int>(req->dst.port));
}

PyObject* py_reply(PyObject*, PyObject* args) {
  int rep;
  const char* host;
  int port;
  if (!PyArg_ParseTuple(args, "isi", &rep, &host, &port)) return nullptr;
  s5::Address bound{host, static_cast<std::uint16_t>(port)};
  return bytes_from(s5::reply(static_cast<std::uint8_t>(rep), bound));
}

// ---- UDP data channel ------------------------------------------------------

PyObject* py_udp_encapsulate(PyObject*, PyObject* args) {
  const char* host;
  int port;
  const char* buf;
  Py_ssize_t len;
  int frag = 0;
  if (!PyArg_ParseTuple(args, "siy#|i", &host, &port, &buf, &len, &frag))
    return nullptr;
  s5::Address dst{host, static_cast<std::uint16_t>(port)};
  return bytes_from(s5::udp_encapsulate(dst, as_span(buf, len),
                                        static_cast<std::uint8_t>(frag)));
}

PyObject* py_udp_decapsulate(PyObject*, PyObject* args) {
  const char* buf;
  Py_ssize_t len;
  if (!PyArg_ParseTuple(args, "y#", &buf, &len)) return nullptr;
  auto d = s5::udp_decapsulate(as_span(buf, len));
  if (!d) Py_RETURN_NONE;
  // (frag, host, port, payload)
  return Py_BuildValue("(isiy#)", static_cast<int>(d->frag),
                       d->origin.host.c_str(), static_cast<int>(d->origin.port),
                       reinterpret_cast<const char*>(d->payload.data()),
                       static_cast<Py_ssize_t>(d->payload.size()));
}

PyMethodDef methods[] = {
    {"client_greeting", py_client_greeting, METH_VARARGS,
     "client_greeting(methods: bytes) -> bytes"},
    {"parse_method_selection", py_parse_method_selection, METH_VARARGS,
     "parse_method_selection(data: bytes) -> int|None"},
    {"userpass_auth", py_userpass_auth, METH_VARARGS,
     "userpass_auth(user: str, password: str) -> bytes"},
    {"parse_auth_reply", py_parse_auth_reply, METH_VARARGS,
     "parse_auth_reply(data: bytes) -> int|None"},
    {"request", py_request, METH_VARARGS,
     "request(cmd: int, host: str, port: int) -> bytes"},
    {"parse_reply", py_parse_reply, METH_VARARGS,
     "parse_reply(data: bytes) -> (rep, host, port)|None"},
    {"parse_greeting", py_parse_greeting, METH_VARARGS,
     "parse_greeting(data: bytes) -> bytes|None: offered method bytes"},
    {"method_selection", py_method_selection, METH_VARARGS,
     "method_selection(method: int) -> bytes"},
    {"parse_userpass", py_parse_userpass, METH_VARARGS,
     "parse_userpass(data: bytes) -> (user, password)|None"},
    {"auth_reply", py_auth_reply, METH_VARARGS,
     "auth_reply(status: int) -> bytes"},
    {"parse_request", py_parse_request, METH_VARARGS,
     "parse_request(data: bytes) -> (cmd, host, port)|None"},
    {"reply", py_reply, METH_VARARGS,
     "reply(rep: int, host: str, port: int) -> bytes"},
    {"udp_encapsulate", py_udp_encapsulate, METH_VARARGS,
     "udp_encapsulate(host, port, payload, frag=0) -> bytes"},
    {"udp_decapsulate", py_udp_decapsulate, METH_VARARGS,
     "udp_decapsulate(data) -> (frag, host, port, payload)|None"},
    {nullptr, nullptr, 0, nullptr}};

PyModuleDef module_def = {PyModuleDef_HEAD_INIT,
                          "_core",
                          "optisocks5 sans-IO SOCKS5 codec (RFC 1928/1929).",
                          -1,
                          methods,
                          nullptr,
                          nullptr,
                          nullptr,
                          nullptr};

}  // namespace

PyMODINIT_FUNC PyInit__core(void) { return PyModule_Create(&module_def); }
