
#include "dissector.h"
#include "utils.h"
#include "dissectorNode.h"
#include <node_buffer.h>
#include <sstream>

/* static */ v8::Persistent<v8::FunctionTemplate> Dissector::s_ct;

// the wireshark header file does not declare this as extern "C" so we need to declare it ourselves
extern "C" {
  extern int wtap_pcap_encap_to_wtap_encap(int encap);
};

Dissector::Dissector(int linkLayerType) : m_linkLayerType(linkLayerType) {
}

/*static*/ void Dissector::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("Dissector"));

  NODE_SET_PROTOTYPE_METHOD(s_ct, "_dissect", dissect);

  target->Set(v8::String::NewSymbol("Dissector"), s_ct->GetFunction());
}

/*static*/ v8::Handle<v8::Value> Dissector::New(const v8::Arguments& args) {
  v8::HandleScope scope;

  REQ_NUMBER_ARG(0, linkLayerType);
  int linkLayerTypeVal = linkLayerType->Value();

  Dissector *self = new Dissector(linkLayerTypeVal);

  cap_file_init(&self->m_cfile);

  // read preferences
  v8::Handle<v8::Value> *error = NULL;
  e_prefs *prefs = self->readPrefs(error);
  if(prefs == NULL) {
    return *error;
  }

  // Build the column format array
  build_column_format_array(&self->m_cfile.cinfo, prefs->num_cols, TRUE);

  self->m_cfile.wth = NULL;
  self->m_cfile.f_datalen = 0;
  self->m_cfile.filename = g_strdup("");
  self->m_cfile.is_tempfile = FALSE;
  self->m_cfile.user_saved = FALSE;
  self->m_cfile.cd_t = WTAP_FILE_UNKNOWN;
  self->m_cfile.count = 0;
  self->m_cfile.drops_known = FALSE;
  self->m_cfile.drops = 0;
  self->m_cfile.has_snap = FALSE;
  self->m_cfile.snap = WTAP_MAX_PACKET_SIZE;
  nstime_set_zero(&self->m_cfile.elapsed_time);

  self->m_encap = wtap_pcap_encap_to_wtap_encap(self->m_linkLayerType);

  nstime_set_unset(&self->m_first_ts);
  nstime_set_unset(&self->m_prev_dis_ts);
  nstime_set_unset(&self->m_prev_cap_ts);

	self->m_data_offset = 0;

  self->Wrap(args.This());
  return args.This();
}

Dissector::~Dissector() {
}

/*static*/ v8::Handle<v8::Value> Dissector::dissect(const v8::Arguments& args) {
  Dissector* self = ObjectWrap::Unwrap<Dissector>(args.This());

	v8::HandleScope handleScope;
  struct wtap_pkthdr whdr;
  guchar *data;
	v8::Local<v8::Object> dataBuffer;

	whdr.pkt_encap = self->m_encap;

	if(args.Length() != 1) {
		return v8::ThrowException(v8::Exception::Error(v8::String::New("Dissect takes 3 arguments.")));
	}

	// no packet information just a buffer
	if(node::Buffer::HasInstance(args[0])) {
		v8::Local<v8::Value> dataBufferValue = args[0];
		dataBuffer = dataBufferValue->ToObject();
		int dataBufferLength = node::Buffer::Length(dataBuffer);
		data = (guchar*)node::Buffer::Data(dataBuffer);
		whdr.ts.secs = 0;
		whdr.ts.nsecs = 0;
		whdr.caplen = dataBufferLength;
		whdr.len = dataBufferLength;
	}

	// packet information with a buffer in the "data" property
	else {
		REQ_OBJECT_ARG(0, packet);
		v8::Local<v8::Value> dataBufferValue = packet->Get(v8::String::New("data"));
		if(dataBufferValue->IsUndefined()) {
			return v8::ThrowException(v8::Exception::Error(v8::String::New("First argument must contain a member 'data' that is a buffer.")));
		}
		dataBuffer = dataBufferValue->ToObject();
		data = (guchar*)node::Buffer::Data(dataBuffer);
		int dataBufferLength = node::Buffer::Length(dataBuffer);

		v8::Local<v8::Value> header = packet->Get(v8::String::New("header"));
		if(header->IsUndefined()) {
			whdr.ts.secs = 0;
			whdr.ts.nsecs = 0;
			whdr.caplen = dataBufferLength;
			whdr.len = dataBufferLength;
		} else {
			v8::Local<v8::Object> headerObj = header->ToObject();
			whdr.ts.secs = getNumberFromV8Object(headerObj, "timestampSeconds", 0);
			whdr.ts.nsecs = getNumberFromV8Object(headerObj, "timestampMicroseconds", 0);
			whdr.caplen = getNumberFromV8Object(headerObj, "capturedLength", dataBufferLength);
			whdr.len = getNumberFromV8Object(headerObj, "originalLength", dataBufferLength);
		}
	}

  frame_data *fdata = new frame_data();
  epan_dissect_t *edt = new epan_dissect_t();
	
  self->m_cfile.count++;
  frame_data_init(fdata, self->m_cfile.count, &whdr, self->m_data_offset, self->m_cum_bytes);
  epan_dissect_init(edt, TRUE, TRUE);
  frame_data_set_before_dissect(fdata, &self->m_cfile.elapsed_time, &self->m_first_ts, &self->m_prev_dis_ts, &self->m_prev_cap_ts);
  epan_dissect_run(edt, &self->m_cfile.pseudo_header, data, fdata, &self->m_cfile.cinfo);
	frame_data_set_after_dissect(fdata, &self->m_cum_bytes, &self->m_prev_dis_ts);
	self->m_data_offset += whdr.caplen;

	v8::Local<v8::Value> result = DissectorNode::New(fdata, edt, edt->tree, v8::Null());	
	
  return handleScope.Close(result);
}

e_prefs* Dissector::readPrefs(v8::Handle<v8::Value> *error) {
  char errorString[1000];
  e_prefs *prefs_p;
  char *gpf_path, *pf_path;
  int gpf_open_errno, gpf_read_errno;
  int pf_open_errno, pf_read_errno;
  prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path, &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      sprintf(errorString, "Can't open global preferences file \"%s\": %s.", pf_path, g_strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      sprintf(errorString, "I/O error reading global preferences file \"%s\": %s.", pf_path, g_strerror(gpf_read_errno));
    }
    *error = v8::ThrowException(v8::Exception::Error(v8::String::New(errorString)));
    return NULL;
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      sprintf(errorString, "Can't open your preferences file \"%s\": %s.", pf_path, g_strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      sprintf(errorString, "I/O error reading your preferences file \"%s\": %s.", pf_path, g_strerror(pf_read_errno));
    }
    g_free(pf_path);
    *error = v8::ThrowException(v8::Exception::Error(v8::String::New(errorString)));
    return NULL;
  }
  return prefs_p;
}
