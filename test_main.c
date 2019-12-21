#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "helper.h"
#include "fixture.h"


START_TEST(test_is_ip_udp) {
	ck_assert(is_ip((struct ether_header *) TEST_FIXTURE_UDP));
} END_TEST

START_TEST(test_is_ip_tcp) {
	ck_assert(is_ip((struct ether_header *) TEST_FIXTURE_TCP));
} END_TEST

START_TEST(test_is_tcp_udp) {
	ck_assert(!is_tcp((struct iphdr *) (TEST_FIXTURE_UDP + 14)));
} END_TEST

START_TEST(test_is_tcp_tcp) {
	ck_assert(is_tcp((struct iphdr *) (TEST_FIXTURE_TCP + 14)));
} END_TEST

START_TEST(test_end_of_ip_tcp) {
	const char *end = TEST_FIXTURE_TCP + 14 + 20 + 32 + 46;
	ck_assert_ptr_eq(end_of_ip((struct iphdr *) (TEST_FIXTURE_TCP + 14)), end);
} END_TEST

START_TEST(test_tcp_payload) {
	const char *data_ptr = TEST_FIXTURE_TCP + 14 + 20 + 32;
	ck_assert_ptr_eq(data_ptr, tcp_payload((struct tcphdr *) (TEST_FIXTURE_TCP + 14 + 20)));
} END_TEST

int main(void) {
	Suite *s;
	TCase *tc;
	SRunner *runner;
	int num_failed = -1;

	s = suite_create("main");
	tc = tcase_create("all");
	tcase_add_test(tc, test_is_ip_udp);
	tcase_add_test(tc, test_is_ip_tcp);
	tcase_add_test(tc, test_is_tcp_udp);
	tcase_add_test(tc, test_is_tcp_tcp);
	tcase_add_test(tc, test_end_of_ip_tcp);
	tcase_add_test(tc, test_tcp_payload);

	suite_add_tcase(s, tc);
	runner = srunner_create(s);
	srunner_run_all(runner, CK_NORMAL);
	num_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
