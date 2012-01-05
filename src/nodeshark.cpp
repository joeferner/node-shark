
#include "nodeshark.h"
#include "dissector.h"

/* static */ v8::Persistent<v8::FunctionTemplate> NodeShark::s_ct;

static void
tshark_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
    const gchar *message, gpointer user_data)
{
  g_log_default_handler(log_domain, log_level, message, user_data);
}

/*static*/ void NodeShark::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(New);
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("NodeShark"));

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
}

/*static*/ v8::Handle<v8::Value> NodeShark::New(const v8::Arguments& args) {
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
    Dissector::Init(target);
  }

  NODE_MODULE(nodeshark_bindings, init);
}
