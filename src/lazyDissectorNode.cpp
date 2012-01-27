
#include "lazyDissectorNode.h"
#include "utils.h"

BENCHMARK_DEF_EXTERN(lazyDissectorNodeNew);

/*static*/ v8::Persistent<v8::FunctionTemplate> LazyDissectorNode::s_ct;

/*static*/ void LazyDissectorNode::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New();
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("LazyNode"));

  target->Set(v8::String::NewSymbol("LazyNode"), s_ct->GetFunction());
}

/*static*/ v8::Local<v8::Object> LazyDissectorNode::New(frame_data *fdata, epan_dissect_t *edt, proto_node *node) {
  v8::HandleScope scope;
  BENCHMARK_START(lazyDissectorNodeNew);
  v8::Local<v8::Function> ctor = s_ct->GetFunction();
  v8::Local<v8::Object> obj = ctor->NewInstance();
  LazyDissectorNode *self = new LazyDissectorNode(fdata, edt, node);
  self->Wrap(obj);
  BENCHMARK_END(lazyDissectorNodeNew);
  return scope.Close(obj);
}

LazyDissectorNode::LazyDissectorNode(frame_data *fdata, epan_dissect_t *edt, proto_node *node) {
  m_fdata = fdata;
  m_edt = edt;
  m_node = node;
}

LazyDissectorNode::~LazyDissectorNode() {

}
