#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "helper.h"

/* TODO: Use a ld script to include these from files */
const char TEST_FIXTURE_UDP[] = {
	0xCE,
	0x20,
	0xE8,
	0x2A,
	0xB0,
	0x0D,
	0xCE,
	0x20,
	0xE8,
	0xA2,
	0x06,
	0x64,
	0x08,
	0x00,
	0x45,
	0x02,
	0x01,
	0x5E,
	0xFD,
	0x0C,
	0x00,
	0x00,
	0x40,
	0x11,
	0xA8,
	0x02,
	0x0A,
	0x8C,
	0x0F,
	0xC1,
	0x1B,
	0xF6,
	0x9E,
	0x3B,
	0xEA,
	0x61,
	0xA7,
	0x41,
	0x01,
	0x4A,
	0xD5,
	0xD9,
	0x80,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x9F,
	0x1F,
	0xFF,
	0x75,
	0x7C,
	0x74,
	0xCB,
	0x2C,
	0x76,
	0x0F,
	0x51,
	0x40,
	0xC2,
	0x1E,
	0x0E,
	0xB5,
	0xF3,
	0x33,
	0xBF,
	0x59,
	0xD5,
	0x63,
	0xBD,
	0x06,
	0xD0,
	0xF6,
	0xDA,
	0xFC,
	0x14,
	0x1F,
	0x89,
	0x29,
	0xAC,
	0x33,
	0xA6,
	0x26,
	0xD2,
	0x6A,
	0xF9,
	0x70,
	0x84,
	0x13,
	0x6B,
	0x7A,
	0x07,
	0x3B,
	0x44,
	0xE4,
	0x54,
	0xC6,
	0xFC,
	0x96,
	0xC4,
	0xE9,
	0x09,
	0x4A,
	0xD2,
	0x8F,
	0xA9,
	0xCC,
	0x95,
	0xDA,
	0x06,
	0xC0,
	0x1F,
	0x8B,
	0xBD,
	0x49,
	0xD1,
	0x4A,
	0x48,
	0x43,
	0x43,
	0x9E,
	0x11,
	0x1B,
	0x38,
	0x18,
	0xB1,
	0x44,
	0x60,
	0x18,
	0xB9,
	0x89,
	0x89,
	0x0A,
	0xC3,
	0x49,
	0x6A,
	0xBE,
	0x91,
	0xB9,
	0xA3,
	0xB0,
	0xC0,
	0x6F,
	0xCF,
	0x6B,
	0x7D,
	0x37,
	0xF3,
	0xE4,
	0x3F,
	0x65,
	0x99,
	0xC8,
	0x5C,
	0x17,
	0x28,
	0x17,
	0xDB,
	0x76,
	0xC4,
	0x62,
	0x6A,
	0x5F,
	0x12,
	0x17,
	0x30,
	0x83,
	0xC7,
	0xA6,
	0xBD,
	0x1D,
	0x06,
	0xD6,
	0x42,
	0x9B,
	0x69,
	0x48,
	0xF6,
	0x67,
	0xCF,
	0x96,
	0x89,
	0x99,
	0xB3,
	0xC4,
	0xCD,
	0x85,
	0x3E,
	0xE2,
	0xD8,
	0x19,
	0xB8,
	0x8C,
	0xF4,
	0x2F,
	0x37,
	0x37,
	0x3A,
	0x23,
	0xFF,
	0x48,
	0x85,
	0xE4,
	0xFA,
	0x18,
	0xBE,
	0xC3,
	0x42,
	0x8E,
	0xCA,
	0xEC,
	0x4F,
	0x60,
	0x3E,
	0x03,
	0x8C,
	0x19,
	0x14,
	0x06,
	0x71,
	0xAA,
	0x61,
	0x66,
	0x6F,
	0x82,
	0x71,
	0xD9,
	0x99,
	0xFA,
	0xDC,
	0xCD,
	0x23,
	0xBC,
	0x00,
	0x15,
	0x8B,
	0xE3,
	0x8F,
	0x63,
	0x31,
	0xAF,
	0x1C,
	0x2E,
	0x03,
	0x03,
	0x20,
	0xB4,
	0x62,
	0x6F,
	0x34,
	0xAF,
	0x3F,
	0xA8,
	0x74,
	0x8F,
	0x54,
	0x6A,
	0xB5,
	0x10,
	0x73,
	0x61,
	0x83,
	0xC8,
	0x77,
	0x55,
	0x0D,
	0x34,
	0xBC,
	0x3B,
	0xB5,
	0x26,
	0x94,
	0xF4,
	0x89,
	0x72,
	0xC9,
	0x44,
	0xC2,
	0x90,
	0xDD,
	0xE2,
	0xC4,
	0x96,
	0xE1,
	0x96,
	0xCC,
	0xED,
	0x2E,
	0x20,
	0xBA,
	0xA8,
	0x32,
	0x6F,
	0x99,
	0xB5,
	0x2B,
	0x06,
	0x86,
	0x62,
	0x96,
	0x4A,
	0x9C,
	0xFD,
	0x4A,
	0x9E,
	0xFA,
	0xC9,
	0x47,
	0x53,
	0x5E,
	0x87,
	0x44,
	0x54,
	0xE1,
	0x80,
	0xB6,
	0xFC,
	0x39,
	0xCB,
	0xD7,
	0xD7,
	0x6E,
	0x99,
	0x3F,
	0xF6,
	0x23,
	0x07,
	0x04,
	0xBB,
	0xB9,
	0x8B,
	0x66,
	0xDB,
	0xC2,
	0x95,
	0xFA,
	0x71,
	0x2E,
	0x23,
	0xD4,
	0x0E,
	0xC9,
	0x16,
	0x9D,
	0x68,
	0xC1,
	0xFA,
	0xD2,
	0xCD,
	0x7F,
	0xAD,
	0x3F,
};

const char TEST_FIXTURE_TCP[] = {
	0xCE,
	0x20,
	0xE8,
	0x2A,
	0xB0,
	0x0D,
	0xCE,
	0x20,
	0xE8,
	0xA2,
	0x06,
	0x64,
	0x08,
	0x00,
	0x45,
	0x00,
	0x00,
	0x62,
	0x68,
	0x13,
	0x00,
	0x00,
	0x35,
	0x06,
	0x0E,
	0xC1,
	0x97,
	0x65,
	0xC1,
	0x45,
	0xAC,
	0x14,
	0x0A,
	0x03,
	0x01,
	0xBB,
	0xEA,
	0x0A,
	0xF8,
	0xF8,
	0xAE,
	0x18,
	0x05,
	0x13,
	0x45,
	0x53,
	0x80,
	0x18,
	0x00,
	0x44,
	0xDD,
	0x83,
	0x00,
	0x00,
	0x01,
	0x01,
	0x08,
	0x0A,
	0x5E,
	0xB0,
	0x5E,
	0x62,
	0x36,
	0xB2,
	0x91,
	0xF9,
	0x17,
	0x03,
	0x03,
	0x00,
	0x29,
	0x32,
	0xF8,
	0xA8,
	0xF7,
	0x13,
	0x6E,
	0xFD,
	0x8C,
	0x36,
	0xBD,
	0x8D,
	0x7E,
	0xBA,
	0x8E,
	0xE8,
	0x17,
	0xAB,
	0xD2,
	0x54,
	0x96,
	0xBA,
	0x98,
	0x02,
	0x3C,
	0x66,
	0xD7,
	0xF2,
	0x44,
	0x0F,
	0x1A,
	0x8B,
	0xA7,
	0xBA,
	0x45,
	0x52,
	0xFB,
	0xF0,
	0xC5,
	0x64,
	0xF3,
	0x96,
};

/* TODO: Test TCP packet without payload */

START_TEST(test_is_ipv4_udp) {
	/* IPv4 UDP packet should return true for is_ipv4 */
	ck_assert(is_ipv4((struct ether_header *) TEST_FIXTURE_UDP));
} END_TEST

START_TEST(test_is_ipv4_tcp) {
	/* IPv4 TCP packet should return true for is_ipv4 */
	ck_assert(is_ipv4((struct ether_header *) TEST_FIXTURE_TCP));
} END_TEST

START_TEST(test_is_tcp_udp) {
	/* IPv4 UDP packet should return false for is_tcp */
	ck_assert(!is_tcp((struct iphdr *) (TEST_FIXTURE_UDP + 14)));
} END_TEST

START_TEST(test_is_tcp_tcp) {
	/* IPv4 TCP packet should return false for is_tcp */
	ck_assert(is_tcp((struct iphdr *) (TEST_FIXTURE_TCP + 14)));
} END_TEST

START_TEST(test_end_of_ip_tcp) {
	/* end_of_ip should point to the end of IP packet */
	const char *end = TEST_FIXTURE_TCP + 14 + 20 + 32 + 46;
	ck_assert_ptr_eq(end_of_ip((struct iphdr *) (TEST_FIXTURE_TCP + 14)), end);
} END_TEST

START_TEST(test_tcp_payload) {
	/* tcp_payload should point to the beginning of TCP payload content */
	const char *data_ptr = TEST_FIXTURE_TCP + 14 + 20 + 32;
	ck_assert_ptr_eq(data_ptr, tcp_payload((struct tcphdr *) (TEST_FIXTURE_TCP + 14 + 20)));
} END_TEST

static size_t mock_data_handler(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	const char *data_ptr = TEST_FIXTURE_TCP + 14 + 20 + 32;
	ck_assert_ptr_eq(ptr, data_ptr);
	ck_assert_int_eq(size, 1);
	ck_assert_int_eq(nmemb, 46);
	ck_assert_ptr_eq(stream, NULL);
	return nmemb;
}

START_TEST(test_packet_handler_tcp) {
	struct pcap_pkthdr pcap_header = {
		.caplen = sizeof(TEST_FIXTURE_TCP),
	};
	struct dispatch_param param = {
		.fd = NULL,
		.data_handler = mock_data_handler,
	};
	/* packet_handler should call the mock_data_handler with the TCP payload data */
	packet_handler((void *) &param, &pcap_header, (u_char *) TEST_FIXTURE_TCP);
} END_TEST

int main(void) {
	Suite *s;
	TCase *tc;
	SRunner *runner;
	int num_failed = -1;

	s = suite_create("main");
	tc = tcase_create("all");
	tcase_add_test(tc, test_is_ipv4_udp);
	tcase_add_test(tc, test_is_ipv4_tcp);
	tcase_add_test(tc, test_is_tcp_udp);
	tcase_add_test(tc, test_is_tcp_tcp);
	tcase_add_test(tc, test_end_of_ip_tcp);
	tcase_add_test(tc, test_tcp_payload);
	tcase_add_test(tc, test_packet_handler_tcp);

	suite_add_tcase(s, tc);
	runner = srunner_create(s);
	srunner_run_all(runner, CK_NORMAL);
	num_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
