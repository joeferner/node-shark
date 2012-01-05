
#include "dissector.h"
#include "utils.h"
#include <node_buffer.h>

extern "C" {
  extern void tap_queue_init(epan_dissect_t *edt);
  extern void tap_push_tapped_queue(epan_dissect_t *edt);
  extern int wtap_pcap_encap_to_wtap_encap(int encap);
};

struct print_data {
  epan_dissect_t *edt;
  int level;
};

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
static const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
	GSList *src_le;
	data_source *src;
	tvbuff_t *src_tvb;
	gint length, tvbuff_length;

	for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
		src = (data_source *)src_le->data;
		src_tvb = src->tvb;
		if (fi->ds_tvb == src_tvb) {
			/*
			 * Found it.
			 *
			 * XXX - a field can have a length that runs past
			 * the end of the tvbuff.  Ideally, that should
			 * be fixed when adding an item to the protocol
			 * tree, but checking the length when doing
			 * that could be expensive.  Until we fix that,
			 * we'll do the check here.
			 */
			tvbuff_length = tvb_length_remaining(src_tvb,
			    fi->start);
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

static void
write_field_hex_value(GSList *src_list, field_info *fi)
{
	int i;
	const guint8 *pd;

	if (!fi->ds_tvb)
		return;

	if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
		printf("field length invalid!");
		return;
	}

	/* Find the data for this field. */
	pd = get_field_data(src_list, fi);

	if (pd) {
		/* Print a simple hex dump */
		for (i = 0 ; i < fi->length; i++) {
			printf("%02x", pd[i]);
		}
	}
}

static
void my_tree_print_node(proto_node *node, gpointer data)
{
  field_info	*fi = PNODE_FINFO(node);
  //gchar		label_str[ITEM_LABEL_LENGTH];
  //gchar		*label_ptr;
  print_data	*pdata = (print_data*) data;
 // const guint8	*pd;

  /* was a free format label produced? */
  /*
	if (fi->rep) {
		label_ptr = fi->rep->representation;
	}
	else { //no, make a generic label
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	}

	if (PROTO_ITEM_IS_GENERATED(node)) {
		label_ptr = g_strdup_printf("[%s]", label_ptr);
	}
  */

  int pos;
  if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
    pos = node->parent->finfo->start + fi->start;
  } else {
    pos = fi->start;
  }


  char		*dfilter_string;
  int chop_len = 0;
  dfilter_string = proto_construct_match_selected_string(fi, pdata->edt);
  if (dfilter_string != NULL) {
    char *p = strstr(dfilter_string, "==");
    if(p) {
      chop_len = (int)(p - dfilter_string) + 3;
    }

    /* XXX - Remove double-quotes. Again, once we
     * can call fvalue_to_string_repr(), we can
     * ask it not to produce the version for
     * display-filters, and thus, no
     * double-quotes. */
    if (dfilter_string[strlen(dfilter_string)-1] == '"') {
        dfilter_string[strlen(dfilter_string)-1] = '\0';
        chop_len++;
    }
  }

  for(int i=0; i<pdata->level; i++) {
    printf("   ");
  }
  printf("%s (size=%d, pos=%d, show=\"%s\"", fi->hfinfo->abbrev, fi->length, pos, &(dfilter_string[chop_len]));

  if(fi->hfinfo->type != FT_PROTOCOL) {
    printf(", val=\"");
    if (fi->length > 0) {
      if (fi->hfinfo->bitmask!=0) {
        printf("%X", fvalue_get_uinteger(&fi->value));
      }
      else {
        write_field_hex_value(pdata->edt->pi.data_src, fi);
      }
    }
    printf("\"");
  }

  printf(")\n");

  /* If it's uninterpreted data, dump it (unless our caller will
   be printing the entire packet in hex). */
	//if (fi->hfinfo->id == proto_data) {
		/*
		 * Find the data for this field.
		 */
    /*
		pd = get_field_data(pdata->edt->pi.data_src, fi);
		if (pd) {
			print_hex_data_buffer(pd, fi->length);
		}
    */
	//}

  if (node->first_child != NULL) {
    pdata->level++;
    proto_tree_children_foreach(node, my_tree_print_node, data);
    pdata->level--;
  }
}


/* static */ v8::Persistent<v8::FunctionTemplate> Dissector::s_ct;

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

  Dissector *client = new Dissector();

  cap_file_init(&client->m_cfile);

  client->Wrap(args.This());
  return args.This();
}

/*static*/ v8::Handle<v8::Value> Dissector::dissect(const v8::Arguments& args) {
  Dissector* self = ObjectWrap::Unwrap<Dissector>(args.This());

  REQ_OBJECT_ARG(0, dataBuffer);

  guchar *data = (guchar*)node::Buffer::Data(dataBuffer);

  e_prefs             *prefs_p;

  // prefs
  char                *gpf_path, *pf_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                       &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
      if (gpf_open_errno != 0) {
          printf("Can't open global preferences file \"%s\": %s.",
                     pf_path, g_strerror(gpf_open_errno));
      }
      if (gpf_read_errno != 0) {
          printf("I/O error reading global preferences file \"%s\": %s.",
                     pf_path, g_strerror(gpf_read_errno));
      }
  }
  if (pf_path != NULL) {
      if (pf_open_errno != 0) {
          printf("Can't open your preferences file \"%s\": %s.", pf_path,
                     g_strerror(pf_open_errno));
      }
      if (pf_read_errno != 0) {
          printf("I/O error reading your preferences file \"%s\": %s.",
                     pf_path, g_strerror(pf_read_errno));
      }
      g_free(pf_path);
      pf_path = NULL;
  }

  /* Build the column format array */
  build_column_format_array(&self->m_cfile.cinfo, prefs_p->num_cols, TRUE);

  //dfilter_t *rfcodes[64];
  //dfilter_compile("frame", &rfcodes[0]);

  /* Cleanup all data structures used for dissection. */
  cleanup_dissection();
  /* Initialize all data structures used for dissection. */
  init_dissection();

  int encap = wtap_pcap_encap_to_wtap_encap(WTAP_ENCAP_ETHERNET);

  self->m_cfile.wth = NULL;
  self->m_cfile.f_datalen = 0;
  self->m_cfile.filename = g_strdup("");
  self->m_cfile.is_tempfile = FALSE;
  self->m_cfile.user_saved = FALSE;
  self->m_cfile.cd_t      = WTAP_FILE_UNKNOWN;
  self->m_cfile.count     = 0;
  self->m_cfile.drops_known = FALSE;
  self->m_cfile.drops     = 0;
  self->m_cfile.has_snap = FALSE;
  self->m_cfile.snap = WTAP_MAX_PACKET_SIZE;
  nstime_set_zero(&self->m_cfile.elapsed_time);

  static nstime_t first_ts;
  static nstime_t prev_dis_ts;
  static nstime_t prev_cap_ts;
  nstime_set_unset(&first_ts);
  nstime_set_unset(&prev_dis_ts);
  nstime_set_unset(&prev_cap_ts);

  frame_data fdata;
  union wtap_pseudo_header pseudo_header;
  struct wtap_pkthdr whdr;

  whdr.ts.secs = 0;
  whdr.ts.nsecs = 0;
  whdr.caplen = 121;
  whdr.len = 121;
  whdr.pkt_encap = encap;

  memset(&pseudo_header, 0, sizeof(pseudo_header));

  self->m_cfile.count++;

  frame_data_init(&fdata, self->m_cfile.count, &whdr, 0, 0);

  epan_dissect_t edt;

  epan_dissect_init(&edt, TRUE, TRUE);

  //printf("rfcodes[0]: %d\n", (int)rfcodes[0]);
  //epan_dissect_prime_dfilter(&edt, rfcodes[0]);

  frame_data_set_before_dissect(&fdata, &self->m_cfile.elapsed_time, &first_ts, &prev_dis_ts, &prev_cap_ts);

  epan_dissect_run(&edt, &pseudo_header, data, &fdata, &self->m_cfile.cinfo);

  print_data pdata;
  pdata.edt = &edt;
  pdata.level = 0;
  proto_tree_children_foreach(edt.tree, my_tree_print_node, &pdata);

  //gboolean passed = dfilter_apply_edt(rfcodes[0], &edt);

  /*gchar buf[1024];
  address_to_str_buf(&edt->pi.src, buf, 1024);
  printf("edt->pi.src: %s\n", buf);*/

  epan_dissect_cleanup(&edt);
  frame_data_cleanup(&fdata);

  return v8::Undefined();
}