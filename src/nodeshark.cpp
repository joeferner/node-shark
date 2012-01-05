
#include "nodeshark.h"
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/plugins.h>
#include <cfile.h>
#include <log.h>
#include <glib.h>

extern "C" {
  extern void tap_queue_init(epan_dissect_t *edt);
  extern void tap_push_tapped_queue(epan_dissect_t *edt);
  extern int wtap_pcap_encap_to_wtap_encap(int encap);
};

v8::Persistent<v8::FunctionTemplate> NodeShark::s_ct;

static void
tshark_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
    const gchar *message, gpointer user_data)
{
  g_log_default_handler(log_domain, log_level, message, user_data);
}

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

/*
 * This routine is based on a routine created by Dan Lasley
 * <DLASLEY@PROMUS.com>.
 *
 * It was modified for Wireshark by Gilbert Ramirez and others.
 */

#define MAX_OFFSET_LEN	8	/* max length of hex offset of bytes */
#define BYTES_PER_LINE	16	/* max byte values printed on a line */
#define HEX_DUMP_LEN	(BYTES_PER_LINE*3)
				/* max number of characters hex dump takes -
				   2 digits plus trailing blank */
#define DATA_DUMP_LEN	(HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
				/* number of characters those bytes take;
				   3 characters per byte of hex dump,
				   2 blanks separating hex from ASCII,
				   1 character per byte of ASCII dump */
#define MAX_LINE_LEN	(MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
				/* number of characters per line;
				   offset, 2 blanks separating offset
				   from data dump, data dump */

static gboolean
print_hex_data_buffer(const guchar *cp, guint length)
{
	register unsigned int ad, i, j, k, l;
	guchar c;
	guchar line[MAX_LINE_LEN + 1];
	unsigned int use_digits;
	static guchar binhex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	/*
	 * How many of the leading digits of the offset will we supply?
	 * We always supply at least 4 digits, but if the maximum offset
	 * won't fit in 4 digits, we use as many digits as will be needed.
	 */
	if (((length - 1) & 0xF0000000) != 0)
		use_digits = 8;	/* need all 8 digits */
	else if (((length - 1) & 0x0F000000) != 0)
		use_digits = 7;	/* need 7 digits */
	else if (((length - 1) & 0x00F00000) != 0)
		use_digits = 6;	/* need 6 digits */
	else if (((length - 1) & 0x000F0000) != 0)
		use_digits = 5;	/* need 5 digits */
	else
		use_digits = 4;	/* we'll supply 4 digits */

	ad = 0;
	i = 0;
	j = 0;
	k = 0;
	while (i < length) {
		if ((i & 15) == 0) {
			/*
			 * Start of a new line.
			 */
			j = 0;
			l = use_digits;
			do {
				l--;
				c = (ad >> (l*4)) & 0xF;
				line[j++] = binhex[c];
			} while (l != 0);
			line[j++] = ' ';
			line[j++] = ' ';
			memset(line+j, ' ', DATA_DUMP_LEN);

			/*
			 * Offset in line of ASCII dump.
			 */
			k = j + HEX_DUMP_LEN + 2;
		}
		c = *cp++;
		line[j++] = binhex[c>>4];
		line[j++] = binhex[c&0xf];
		j++;
		line[k++] = c >= ' ' && c < 0x7f ? c : '.';
		i++;
		if ((i & 15) == 0 || i == length) {
			/*
			 * We'll be starting a new line, or
			 * we're finished printing this buffer;
			 * dump out the line we've constructed,
			 * and advance the offset.
			 */
			line[k] = '\0';
			printf("   %s\n", (const char*)line);
			ad += 16;
		}
	}
	return TRUE;
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
  const guint8	*pd;

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


/*static*/ void NodeShark::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("NodeShark"));

  NODE_SET_PROTOTYPE_METHOD(s_ct, "doIt", doIt);

  target->Set(v8::String::NewSymbol("NodeShark"), s_ct->GetFunction());

  init_process_policies();

  /* nothing more than the standard GLib handler, but without a warning */
  GLogLevelFlags log_flags = (GLogLevelFlags)(
                    G_LOG_LEVEL_ERROR|
                    G_LOG_LEVEL_CRITICAL|
                    G_LOG_LEVEL_WARNING|
                    G_LOG_LEVEL_MESSAGE|
                    G_LOG_LEVEL_INFO|
                    G_LOG_LEVEL_DEBUG|
                    G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION);

  g_log_set_handler(NULL,
                    log_flags,
                    tshark_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
                    log_flags,
                    tshark_log_handler, NULL /* user_data */);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);


  epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL,
            failureMessage, openFailureMessage, readFailureMessage,
            writeFailureMessage);

  prefs_register_modules();

  // locale
  setlocale(LC_ALL, "");

  // prefs
  char                *gpf_path, *pf_path;
  e_prefs             *prefs_p;
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

  capture_file cfile;
  cap_file_init(&cfile);

  prefs_apply_all();

  /* Build the column format array */
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

  //dfilter_t *rfcodes[64];
  //dfilter_compile("frame", &rfcodes[0]);

  /* Cleanup all data structures used for dissection. */
  cleanup_dissection();
  /* Initialize all data structures used for dissection. */
  init_dissection();

  int encap = wtap_pcap_encap_to_wtap_encap(WTAP_ENCAP_ETHERNET);
  printf("encap: %d\n", encap);

  cfile.wth = NULL;
  cfile.f_datalen = 0;
  cfile.filename = g_strdup("");
  cfile.is_tempfile = FALSE;
  cfile.user_saved = FALSE;
  cfile.cd_t      = WTAP_FILE_UNKNOWN;
  cfile.count     = 0;
  cfile.drops_known = FALSE;
  cfile.drops     = 0;
  cfile.has_snap = FALSE;
  cfile.snap = WTAP_MAX_PACKET_SIZE;
  nstime_set_zero(&cfile.elapsed_time);

  static nstime_t first_ts;
  static nstime_t prev_dis_ts;
  static nstime_t prev_cap_ts;
  nstime_set_unset(&first_ts);
  nstime_set_unset(&prev_dis_ts);
  nstime_set_unset(&prev_cap_ts);

  frame_data fdata;
  union wtap_pseudo_header pseudo_header;
  struct wtap_pkthdr whdr;
  /*
  guchar data[WTAP_MAX_PACKET_SIZE] = {
    //0x66, 0x44, 0x03, 0x4f, 0x69, 0x9b, 0x0a, 0x00, 0x79, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x6d, 0xf8, 0xe6, 0x29, 0x00, 0x00, 0x00, 0x00,
    0x12, 0x48, 0x8f, 0x09, 0x80, 0x04, 0xb3, 0xab, 0x00, 0x08, 0x09, 0x2c, 0x00, 0x58, 0x6d, 0x8f,
    0x67, 0x8a, 0x4f, 0x94, 0x63, 0xd1, 0x26, 0x07, 0x14, 0x58, 0x6d, 0x8f, 0x67, 0x8a, 0x4d, 0x50,
    0x13, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0x08, 0x39, 0x40,
    0x00, 0x40, 0x11, 0x8f, 0x56, 0x0a, 0x14, 0x08, 0x64, 0xc0, 0xa8, 0xd0, 0x01, 0xed, 0x2e, 0x00,
    0x35, 0x00, 0x28, 0x9d, 0xb6, 0xe9, 0x44, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x69, 0x6d, 0x61, 0x70, 0x05, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xea, 0xe9, 0x5a, 0x39
  };
  */
  guchar data[WTAP_MAX_PACKET_SIZE] = {
    0x58, 0x6d, 0x8f, 0x67, 0x8a, 0x4d, 0x00, 0x1b, 0x21, 0xcf, 0xa1, 0x00, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x3b, 0xd1, 0xb0, 0x40, 0x00, 0x40, 0x11, 0xc5, 0xde, 0x0a, 0x14, 0x08, 0x65, 0xc0, 0xa8,
    0xd0, 0x01, 0xc5, 0x32, 0x00, 0x35, 0x00, 0x27, 0xa3, 0x5b, 0x65, 0x89, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0x04, 0x6c, 0x69, 0x76, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
  };


  whdr.ts.secs = 0;
  whdr.ts.nsecs = 0;
  whdr.caplen = 121;
  whdr.len = 121;
  whdr.pkt_encap = encap;

  memset(&pseudo_header, 0, sizeof(pseudo_header));

  cfile.count++;

  frame_data_init(&fdata, cfile.count, &whdr, 0, 0);

  epan_dissect_t edt;

  epan_dissect_init(&edt, TRUE, TRUE);

  //printf("rfcodes[0]: %d\n", (int)rfcodes[0]);
  //epan_dissect_prime_dfilter(&edt, rfcodes[0]);

  frame_data_set_before_dissect(&fdata, &cfile.elapsed_time, &first_ts, &prev_dis_ts, &prev_cap_ts);

  printf("run\n");
  epan_dissect_run(&edt, &pseudo_header, data, &fdata, &cfile.cinfo);

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
}

/*static*/ v8::Handle<v8::Value> NodeShark::New(const v8::Arguments& args) {
  return v8::Undefined();
}

/*static*/ v8::Handle<v8::Value> NodeShark::doIt(const v8::Arguments& args) {
  return v8::Undefined();
}

/*
 * Open/create errors are reported with an console message in TShark.
 */
/*static*/ void NodeShark::openFailureMessage(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "nodeshark: filename: %s, err: %d\n", filename, err);
}

/*
 * General errors are reported with an console message in TShark.
 */
/*static*/ void NodeShark::failureMessage(const char *msg_format, va_list ap)
{
  fprintf(stderr, "nodeshark: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in TShark.
 */
/*static*/ void NodeShark::readFailureMessage(const char *filename, int err)
{
  fprintf(stderr, "nodeshark: An error occurred while reading from the file \"%s\": %s.", filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in TShark.
 */
/*static*/ void NodeShark::writeFailureMessage(const char *filename, int err)
{
  fprintf(stderr, "nodeshark: An error occurred while writing to the file \"%s\": %s.", filename, g_strerror(err));
}

extern "C" {
  static void init(v8::Handle<v8::Object> target) {
    NodeShark::Init(target);
  }

  NODE_MODULE(nodeshark_bindings, init);
}
