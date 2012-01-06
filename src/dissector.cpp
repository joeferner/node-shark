
#include "dissector.h"
#include "utils.h"
#include <node_buffer.h>
#include <sstream>

/* static */ v8::Persistent<v8::FunctionTemplate> Dissector::s_ct;

// the wireshark header file does not declare this as extern "C" so we need to declare it ourselves
extern "C" {
  extern int wtap_pcap_encap_to_wtap_encap(int encap);
};

Dissector::Dissector(int linkLayerType) : m_linkLayerType(linkLayerType) {
}

struct TreeToObjectData {
  epan_dissect_t *edt;
  v8::Local<v8::Object> root;
  v8::Local<v8::Object> parent;
  const char* parentName;
};

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
/*static*/ const guint8 *Dissector::getFieldData(GSList *src_list, field_info *fi)
{
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;
	gint length, tvbuff_length;

	for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
		src = (data_source *)src_le->data;
		src_tvb = src->tvb;
		if (fi->ds_tvb == src_tvb) {
			tvbuff_length = tvb_length_remaining(src_tvb, fi->start);
			if (tvbuff_length < 0) {
				return NULL;
			}
			length = fi->length;
			if (length > tvbuff_length)
				length = tvbuff_length;
			return tvb_get_ptr(src_tvb, fi->start, length);
		}
	}
	g_assert_not_reached();
	return NULL;	/* not found */
}

/*static*/ std::string Dissector::getFieldHexValue(GSList *src_list, field_info *fi)
{
	int i;
	const guint8 *pd;
  std::ostringstream result;

	if (!fi->ds_tvb)
		return "";

	if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
		return "field length invalid!";
	}

	/* Find the data for this field. */
	pd = getFieldData(src_list, fi);

	if (pd) {
		/* Print a simple hex dump */
		for (i = 0 ; i < fi->length; i++) {
      if(i != 0) {
        result << " ";
      }
      char temp[10];
			sprintf(temp, "%02x", pd[i]);
      result << temp;
		}
	}

  return result.str();
}

void Dissector::treeToObject(proto_node *node, gpointer data)
{
  field_info *fi = PNODE_FINFO(node);
  TreeToObjectData *pdata = (TreeToObjectData*) data;
  v8::Local<v8::Object> childObj = v8::Object::New();

  int posInPacket;
  if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
    posInPacket = node->parent->finfo->start + fi->start;
  } else {
    posInPacket = fi->start;
  }

  char *showString;
  int showStringChopPos = 0;
  showString = proto_construct_match_selected_string(fi, pdata->edt);
  if (showString != NULL) {
    char *p = strstr(showString, "==");
    if(p) {
      showStringChopPos = (int)(p - showString) + 3;
    }

    if (showString[strlen(showString)-1] == '"') {
        showString[strlen(showString)-1] = '\0';
        showStringChopPos++;
    }
  }

  childObj->Set(v8::String::New("sizeInPacket"), v8::Integer::New(fi->length));
  childObj->Set(v8::String::New("posInPacket"), v8::Integer::New(posInPacket));
	if(showString) {
		childObj->Set(v8::String::New("showValue"), v8::String::New(&(showString[showStringChopPos])));
	}

  if(fi->hfinfo->type != FT_PROTOCOL) {
    if (fi->length > 0) {
      if (fi->hfinfo->bitmask!=0) {
        childObj->Set(v8::String::New("value"), v8::Integer::New(fvalue_get_uinteger(&fi->value)));
      }
      else {
        std::string str = getFieldHexValue(pdata->edt->pi.data_src, fi);
        childObj->Set(v8::String::New("value"), v8::String::New(str.c_str()));
      }
    }
  }

	const char *name;
	int freeName = false;
	if(!strcmp(fi->hfinfo->abbrev, "text")) {
		gchar label_str[ITEM_LABEL_LENGTH];
		if (fi->rep) {
			name = fi->rep->representation;
		}
		else { /* no, make a generic label */
			name = label_str;
			proto_item_fill_label(fi, label_str);
		}
		if (PROTO_ITEM_IS_GENERATED(node)) {
			name = g_strdup_printf("[%s]", name);
			freeName = true;
		}
	} else {
		int offset = 0;
		int parentNameLength = strlen(pdata->parentName);
		if(!strncmp(fi->hfinfo->abbrev, pdata->parentName, parentNameLength)) {
			offset = parentNameLength;
			if(fi->hfinfo->abbrev[offset] == '.') {
				offset++;
			}
		}
		name = &fi->hfinfo->abbrev[offset];
	}
  pdata->parent->Set(v8::String::New(name), childObj);

	if (freeName) {
		g_free((char*)name);
	}

  if (node->first_child != NULL) {
    v8::Local<v8::Object> lastObj = pdata->parent;
    const char* lastParentName = pdata->parentName;
    pdata->parent = childObj;
    pdata->parentName = fi->hfinfo->abbrev;
    proto_tree_children_foreach(node, Dissector::treeToObject, data);
    pdata->parent = lastObj;
    pdata->parentName = lastParentName;
  }
}

/*static*/ void Dissector::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("Dissector"));

  NODE_SET_PROTOTYPE_METHOD(s_ct, "dissect", dissect);

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

  struct wtap_pkthdr whdr;
  guchar *data;

	whdr.pkt_encap = self->m_encap;

	// no packet information just a buffer
	if(node::Buffer::HasInstance(args[0])) {
		v8::Local<v8::Value> dataBufferValue = args[0];
		v8::Local<v8::Object> dataBuffer = dataBufferValue->ToObject();
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
		v8::Local<v8::Object> dataBuffer = dataBufferValue->ToObject();
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

  frame_data fdata;

  self->m_cfile.count++;
  frame_data_init(&fdata, self->m_cfile.count, &whdr, self->m_data_offset, self->m_cum_bytes);
  epan_dissect_init(&self->m_edt, TRUE, TRUE);
  frame_data_set_before_dissect(&fdata, &self->m_cfile.elapsed_time, &self->m_first_ts, &self->m_prev_dis_ts, &self->m_prev_cap_ts);
  epan_dissect_run(&self->m_edt, &self->m_cfile.pseudo_header, data, &fdata, &self->m_cfile.cinfo);
	frame_data_set_after_dissect(&fdata, &self->m_cum_bytes, &self->m_prev_dis_ts);
	self->m_data_offset += whdr.caplen;

  TreeToObjectData pdata;
  pdata.edt = &self->m_edt;
  pdata.root = pdata.parent = v8::Object::New();
  pdata.parentName = "";
  proto_tree_children_foreach(self->m_edt.tree, treeToObject, &pdata);

  epan_dissect_cleanup(&self->m_edt);
  frame_data_cleanup(&fdata);

  return pdata.root;
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
