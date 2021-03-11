<?php
use FusionsPim\PhpPasswordChecker\{PasswordChecker, PasswordException};
use PHPUnit\Framework\TestCase;

class PasswordCheckerTest extends TestCase
{
    protected function setUp(): void
    {
        $this->checker = new PasswordChecker(['appname', 'companyname', 'companyltd', 'robert', 'smith', 'bob@example.com']);
        $this->checker->setPreviousPasswords([
            '$2y$11$V8Tvqr3nyMMQrR1xE/IFgepTahAprWKWfoh.xgN7ziWdwYRsZyzCu', // couldyouhearme2
            '$2y$11$AFhINRcNKiKR/OKAb8Is8uxovaHMjHhpsVxP8rULLoJRkGi7hhXYa', // couldyouhearmeb4
        ]);
    }

    public function test_valid_with_no_options(): void
    {
        $this->assertTrue((new PasswordChecker)->validate('Canyouhearme1*'));
    }

    public function test_passes_due_to_new_password(): void
    {
        $this->assertTrue($this->checker->validate('Canyouhearme1*'));
    }

    public function test_fails_due_to_confirmation_mismatch(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New and confirmation passwords are different');

        $this->checker->setConfirmation('canyouhearme0');
        $this->checker->validate('canyouhearme1');
    }

    public function test_fails_due_to_short_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password must be at least 10 characters long');

        $this->checker->validate('abc');
    }

    public function test_fails_due_to_customized_length(): void
    {
        $this->checker->setMinLength(14);

        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password must be at least 14 characters long');

        $this->checker->validate('canyouhearme1');
    }

    /**
     * @dataProvider fails_due_to_character_requirements_data_provider
     *
     * @param mixed $requirements
     * @param mixed $password
     * @param mixed $expectedError
     */
    public function test_fails_due_to_character_requirements($requirements, $password, $expectedError): void
    {
        $this->checker->setComplexityRequirements($requirements);

        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage($expectedError);

        $this->checker->validate($password);
    }

    public function fails_due_to_character_requirements_data_provider(): iterable
    {
        $allRequirements = [
            PasswordChecker::REQUIRE_LOWERCASE,
            PasswordChecker::REQUIRE_UPPERCASE,
            PasswordChecker::REQUIRE_NUMBER,
            PasswordChecker::REQUIRE_SYMBOL,
        ];

        return [
            [$allRequirements, 'canyouhearme', 'New password should contain 1 upper case letter, 1 number and 1 symbol'],
            [$allRequirements, 'canyouhearme1', 'New password should contain 1 upper case letter and 1 symbol'],
            [$allRequirements, 'canyouhearme1*', 'New password should contain 1 upper case letter'],
            [$allRequirements, 'Canyouhearme1', 'New password should contain 1 symbol'],
            [[PasswordChecker::REQUIRE_UPPERCASE], 'canyouhearme1', 'New password should contain 1 upper case letter'],
        ];
    }

    public function test_fails_due_to_short_multibyte_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password must be at least 10 characters long');

        $this->checker->validate('åèäèå');
    }

    public function test_fails_due_to_common_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too common, choose another');

        $this->checker->validate('1q2W3e4R5t');
    }

    public function test_fails_due_to_obvious_company_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('companyltd');
    }

    public function test_fails_due_to_obvious_joined_name_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('robertsmith');
    }

    public function test_fails_due_to_obvious_spaced_name_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('robert smith');
    }

    public function test_fails_due_to_obvious_uk_phone_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('07777123456');
    }

    public function test_fails_due_to_obvious_us_phone_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('123-456-7890');
    }

    public function test_fails_due_to_obvious_dob_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('1979-01-23');
    }

    public function test_fails_due_to_obvious_date_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password is too obvious, choose another');

        $this->checker->validate('31/12/1999');
    }

    public function test_fails_due_to_being_current_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password has been used previously, choose another');

        $this->checker->validate('couldyouhearme2');
    }

    public function test_fails_due_to_previous_password(): void
    {
        $this->expectException(PasswordException::class);
        $this->expectExceptionMessage('New password has been used previously, choose another');

        $this->checker->validate('couldyouhearmeb4');
    }
}
