<?php
use FusionsPim\PhpPasswordChecker\PasswordChecker;
use PHPUnit\Framework\TestCase;

class PasswordCheckerTest extends TestCase
{
    protected function setUp()
    {
        $this->checker = new PasswordChecker(['appname', 'companyname', 'companyltd', 'robert', 'smith', 'bob@example.com']);
        $this->checker->setPreviousPasswords([
            '$2y$11$V8Tvqr3nyMMQrR1xE/IFgepTahAprWKWfoh.xgN7ziWdwYRsZyzCu', // couldyouhearme2
            '$2y$11$AFhINRcNKiKR/OKAb8Is8uxovaHMjHhpsVxP8rULLoJRkGi7hhXYa', // couldyouhearmeb4
        ]);
    }

    public function test_valid_with_no_options()
    {
        $this->assertTrue((new PasswordChecker)->validate('canyouhearme1'));
    }

    public function test_passes_due_to_new_password()
    {
        $this->assertTrue($this->checker->validate('canyouhearme1'));
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New and confirmation passwords are different
     */
    public function test_fails_due_to_confirmation_mismatch()
    {
        $this->checker->setConfirmation('canyouhearme0');
        $this->checker->validate('canyouhearme1');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password must be at least 10 characters long
     */
    public function test_fails_due_to_short_password()
    {
        $this->checker->validate('abc');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password must be at least 10 characters long
     */
    public function test_fails_due_to_short_multibyte_password()
    {
        $this->checker->validate('åèäèå');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too common, choose another
     */
    public function test_fails_due_to_common_password()
    {
        $this->checker->validate('1q2W3e4R5t');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_company_password()
    {
        $this->checker->validate('companyltd');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_joined_name_password()
    {
        $this->checker->validate('robertsmith');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_spaced_name_password()
    {
        $this->checker->validate('robert smith');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_uk_phone_password()
    {
        $this->checker->validate('07777123456');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_us_phone_password()
    {
        $this->checker->validate('123-456-7890');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_dob_password()
    {
        $this->checker->validate('1979-01-23');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password is too obvious, choose another
     */
    public function test_fails_due_to_obvious_date_password()
    {
        $this->checker->validate('31/12/1999');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password has been used previously, choose another
     */
    public function test_fails_due_to_being_current_password()
    {
        $this->checker->validate('couldyouhearme2');
    }

    /**
     * @expectedException        FusionsPim\PhpPasswordChecker\PasswordException
     * @expectedExceptionMessage New password has been used previously, choose another
     */
    public function test_fails_due_to_previous_password()
    {
        $this->checker->validate('couldyouhearmeb4');
    }
}
