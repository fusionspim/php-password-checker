<?php
use FusionsPim\PhpPasswordChecker\PasswordChecker;
use PHPUnit\Framework\TestCase;

class PasswordCheckerTest extends TestCase
{
    const APP_SPECIFIC_OBVIOUS_PASSWORDS = ['appname', 'companyname', 'companyltd', 'robert', 'smith', 'bob@example.com'];
    const USER_PASSWORD_HISTORY          = [
        '$2y$11$V8Tvqr3nyMMQrR1xE/IFgepTahAprWKWfoh.xgN7ziWdwYRsZyzCu', // couldyouhearme2
        '$2y$11$AFhINRcNKiKR/OKAb8Is8uxovaHMjHhpsVxP8rULLoJRkGi7hhXYa', // couldyouhearmeb4
    ];

    public function test_passes_due_to_new_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertTrue($checker->validate('canyouhearme1', static::USER_PASSWORD_HISTORY));
        $this->assertNull($checker->getErrorMessage());
    }

    public function test_fails_due_to_short_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('abc', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password must be at least 10 characters long', $checker->getErrorMessage());
    }

    public function test_fails_due_to_common_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('1q2W3e4R5t', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password is too common, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_obvious_company_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('companyltd', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password is too obvious, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_obvious_name_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('robertsmith', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password is too obvious, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_obvious_phone_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('07777123456', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password is too obvious, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_obvious_dob_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('1979-01-23', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password is too obvious, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_being_current_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('couldyouhearme2', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password has been used previously, choose another', $checker->getErrorMessage());
    }

    public function test_fails_due_to_previous_password()
    {
        $checker = new PasswordChecker(static::APP_SPECIFIC_OBVIOUS_PASSWORDS);
        $this->assertFalse($checker->validate('couldyouhearmeb4', static::USER_PASSWORD_HISTORY));
        $this->assertEquals('New password has been used previously, choose another', $checker->getErrorMessage());
    }
}
