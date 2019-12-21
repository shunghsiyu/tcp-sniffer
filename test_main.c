#include <check.h>
#include <stdlib.h>

START_TEST(test_pass) {
	ck_assert_int_eq(1, 1);
} END_TEST

int main(void) {
	Suite *s;
	TCase *tc;
	SRunner *runner;
	int num_failed = -1;

	s = suite_create("main");
	tc = tcase_create("all");
	tcase_add_test(tc, test_pass);
	suite_add_tcase(s, tc);
	runner = srunner_create(s);
	srunner_run_all(runner, CK_NORMAL);
	num_failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
