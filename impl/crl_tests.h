
/**
 * @brief message is a buffer for storing the formatted message. Format is a format string for the message,
 * the format string must be in the form "%d _message_". assert_i is incremented and keeps track of which
 * assert failed.
 * 
 */
#define mu_assert(message, format, test, assert_i) do { \
    if (!(test)) { \
        sprintf(message, format, assert_i); \
        return message; \
    } \
    assert_i++; \
} while (0)

#define mu_run_test(test) do { char *message = test(); tests_run++; \
                            if (message) return message; } while (0)
extern int tests_run;

char mu_msg_buffer[512];