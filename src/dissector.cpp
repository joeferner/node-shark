
#include "dissector.h"
#include "utils.h"
#include "dissectorNode.h"
#include <node_buffer.h>
#include <sstream>
#include "disabled_protos.h"

/* for string manipulation as input for prefs_set_pref() */
#include <glib.h>

BENCHMARK_GLOBAL_DEF();
BENCHMARK_DEF(epanDissect);
BENCHMARK_DEF(dissect);
BENCHMARK_DEF(dissectorNodeNew);
BENCHMARK_DEF(dissectorNodeNewRoot);
BENCHMARK_DEF(createChildren);
BENCHMARK_DEF(createChildrenItem);
BENCHMARK_DEF(getAbbreviation);
BENCHMARK_DEF(lazyDissectorNodeNew);

/* static */ v8::Persistent<v8::FunctionTemplate> Dissector::s_ct;

// the wireshark header file does not declare this as extern "C" so we need to declare it ourselves
extern "C" {
  extern int wtap_pcap_encap_to_wtap_encap(int encap);
};

/* from wireshark/epan/prefs.h */
//extern "C" {
//  extern prefs_set_pref_e prefs_set_pref(char *prefarg);
//};

Dissector::Dissector(int linkLayerType) : m_linkLayerType(linkLayerType) {
}

/*static*/ void Dissector::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("Dissector"));

  NODE_SET_PROTOTYPE_METHOD(s_ct, "_dissect", dissect);
  NODE_SET_PROTOTYPE_METHOD(s_ct, "close", close);

  target->Set(v8::String::NewSymbol("Dissector"), s_ct->GetFunction());
}

/*static*/ v8::Handle<v8::Value> Dissector::New(const v8::Arguments& args) {
  v8::HandleScope scope;
  char errorString[1000];
  dissector_handle_t dhandle;
  prefs_set_pref_e pref_e;
  int dp_read;
  GString *pref_str;

  BENCHMARK_GLOBAL_START();

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
  // read disabled_protocols
//  dp_read= self->readDisabledProtos(error);

  // Build the column format array
  build_column_format_array(&self->m_cfile.cinfo, prefs->num_cols, TRUE);

  self->m_cfile.wth = NULL;
  self->m_cfile.f_datalen = 0;
  self->m_cfile.filename = NULL;
  self->m_cfile.is_tempfile = TRUE;
  self->m_cfile.unsaved_changes = FALSE;
  self->m_cfile.cd_t = WTAP_FILE_UNKNOWN;
  self->m_cfile.count = 0;
  self->m_cfile.drops_known = FALSE;
  self->m_cfile.drops = 0;
  self->m_cfile.has_snap = FALSE;
  self->m_cfile.snap = WTAP_MAX_PACKET_SIZE;
  nstime_set_zero(&self->m_cfile.elapsed_time);

  /*self->m_encap = wtap_pcap_encap_to_wtap_encap(self->m_linkLayerType);*/
  /* see set_link_type() in http://anonsvn.wireshark.org/viewvc/trunk-1.8/rawshark.c?revision=48199&view=co */
  #define LINK_LAYER_TYPE_ETHERNET 1
  #define PROTO_FRP 5001
  if (self->m_linkLayerType == LINK_LAYER_TYPE_ETHERNET) {
   self->m_encap = wtap_pcap_encap_to_wtap_encap(self->m_linkLayerType);
  } else if (self->m_linkLayerType == PROTO_FRP) {
   dhandle= find_dissector("frp");
   if (dhandle) {
    self->m_encap = WTAP_ENCAP_USER0;
    /* "User 0 (DLT=147)","frp","0","","0",""     see ~/.wireshark/user_dlts  */
    //pref_e= prefs_set_pref("uat:user_dlts:\"User 0 (DLT=147)\",\"frp\",\"0\",\"\",\"0\",\"\"");
    pref_str = g_string_new("uat:user_dlts:");
    g_string_append_printf(pref_str, "\"User 0 (DLT=147)\",\"%s\",\"0\",\"\",\"0\",\"\"", "frp");
    sprintf(errorString, "before prefs_set_pref()");
    pref_e= prefs_set_pref(pref_str->str);
    g_string_free(pref_str, TRUE);
    if (pref_e != PREFS_SET_OK) {
     sprintf(errorString, "prefs_set_pref() failed: pref_e= %i", pref_e);
     //return pref_e;
    }
   }
  }

  /* disable dissectors as per list read above from disabled_protocolls files */
  if (dp_read) {
//   set_disabled_protos_list();
  }

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
  v8::HandleScope handleScope;

  BENCHMARK_START(dissect);
  Dissector* self = ObjectWrap::Unwrap<Dissector>(args.This());

  struct wtap_pkthdr whdr;
  guchar *data;
  v8::Local<v8::Object> dataBuffer;

  whdr.pkt_encap = self->m_encap;

  if(args.Length() != 1) {
    return v8::ThrowException(v8::Exception::Error(v8::String::New("Dissect takes 1 arguments.")));
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

  BENCHMARK_START(epanDissect);
  self->m_cfile.count++;
  frame_data_init(fdata, self->m_cfile.count, &whdr, self->m_data_offset, self->m_cum_bytes);
  epan_dissect_init(edt, TRUE, TRUE);
  frame_data_set_before_dissect(fdata, &self->m_cfile.elapsed_time, &self->m_first_ts, &self->m_prev_dis_ts, &self->m_prev_cap_ts);
  epan_dissect_run(edt, &self->m_cfile.pseudo_header, data, fdata, &self->m_cfile.cinfo);
  frame_data_set_after_dissect(fdata, &self->m_cum_bytes, &self->m_prev_dis_ts);
  self->m_data_offset += whdr.caplen;
  BENCHMARK_END(epanDissect);

  v8::Local<v8::Value> result = DissectorNode::New(NULL, fdata, edt, edt->tree);

  BENCHMARK_END(dissect);
  return handleScope.Close(result);
}

/*static*/ v8::Handle<v8::Value> Dissector::close(const v8::Arguments& args) {
  v8::HandleScope handleScope;
  #ifdef BENCHMARK
    Dissector* self = node::ObjectWrap::Unwrap<Dissector>(args.This());
  #endif

  BENCHMARK_GLOBAL_END();

  BENCHMARK_PRINT_START();
  BENCHMARK_PRINT(dissect);
  BENCHMARK_PRINT(epanDissect);
  BENCHMARK_PRINT(dissectorNodeNew);
  BENCHMARK_PRINT(dissectorNodeNewRoot);
  BENCHMARK_PRINT(createChildren);
  BENCHMARK_PRINT(createChildrenItem);
  BENCHMARK_PRINT(getAbbreviation);
  BENCHMARK_PRINT(lazyDissectorNodeNew);
  BENCHMARK_PRINT_END();

  #ifdef BENCHMARK
    printf("packet count: %d\n", self->m_cfile.count);
  #endif

  return v8::Undefined();
}

/* read .wireshark/preferences ... ,  see read_prefs() in
  http://anonsvn.wireshark.org/viewvc/trunk-1.8/rawshark.c?revision=48199&view=co */
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

/* read .wireshark/disabled_protocols ..., see read_disabled_protos_list() in
  http://anonsvn.wireshark.org/viewvc/trunk-1.8/rawshark.c?revision=48199&view=co */
int Dissector::readDisabledProtos(v8::Handle<v8::Value> *error) {
  char errorString[1000];
  char *gdp_path, *dp_path;
  int gdp_open_errno, gdp_read_errno;
  int dp_open_errno, dp_read_errno;

  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                            &dp_path, &dp_open_errno, &dp_read_errno);
  if (gdp_path != NULL) {
      if (gdp_open_errno != 0) {
        sprintf(errorString, "Could not open global disabled protocols file\n\"%s\": %s.",
                     gdp_path, g_strerror(gdp_open_errno));
      }
      if (gdp_read_errno != 0) {
        sprintf(errorString, "I/O error reading global disabled protocols file\n\"%s\": %s.",
                     gdp_path, g_strerror(gdp_read_errno));
      }
      g_free(gdp_path);
     *error = v8::ThrowException(v8::Exception::Error(v8::String::New(errorString)));
  }
  if (dp_path != NULL) {
      if (dp_open_errno != 0) {
        sprintf(errorString, "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
              g_strerror(dp_open_errno));
      }
      if (dp_read_errno != 0) {
        sprintf(errorString, "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
              g_strerror(dp_read_errno));
      }
      g_free(dp_path);
      *error = v8::ThrowException(v8::Exception::Error(v8::String::New(errorString)));
  }
 return (gdp_path == NULL && dp_path == NULL);
}

