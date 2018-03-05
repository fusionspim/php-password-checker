<?php
namespace FusionsPim\PhpPasswordChecker;

class PasswordChecker
{
    private const MIN_LENGTH = 10; // Tied to the filtered password-blacklist.txt

    private $confirm;
    private $recentHashes;
    private $rejectAsTooObvious;

    public function __construct(array $rejectAsTooObvious = [])
    {
        $this->rejectAsTooObvious = $rejectAsTooObvious;
    }

    public function setConfirmation(string $confirm): void
    {
        $this->confirm = $confirm;
    }

    public function setPreviousPasswords(array $recentHashes = []): void
    {
        $this->recentHashes = $recentHashes;
    }

    public function validate(string $password): bool
    {
        if (isset($this->confirm) && $this->confirm !== $password) {
            throw new PasswordException('New and confirmation passwords are different');
        } elseif (mb_strlen($password) < static::MIN_LENGTH) {
            throw new PasswordException(sprintf('New password must be at least %d characters long', static::MIN_LENGTH));
        } elseif ($this->isPasswordBlacklisted($password)) {
            throw new PasswordException('New password is too common, choose another');
        } elseif ($this->isPasswordObvious($password)) {
            throw new PasswordException('New password is too obvious, choose another');
        } elseif ($this->isRecentPassword($password)) {
            throw new PasswordException('New password has been used previously, choose another');
        }

        return true;
    }

    /**
     * @see: https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_100000.txt
     * @note: All passwords with less than MIN_LENGTH characters have been removed from the file
     */
    private function isPasswordBlacklisted(string $password): bool
    {
        return in_array(strtoupper($password), preg_split('/\v+/', strtoupper(
            file_get_contents(__DIR__ . '/../resources/password-blacklist.txt')
        )));
    }

    private function isPasswordObvious(string $password): bool
    {
        foreach ($this->rejectAsTooObvious as $obvious) {
            if (strpos(strtolower($password), strtolower($obvious)) !== false) {
                return true;
            }
        }

        return is_numeric(str_replace([' ', '/', '-'], '', $password)); // Could be a DOB or phone number
    }

    private function isRecentPassword(string $password): bool
    {
        foreach ($this->recentHashes as $hash) {
            if (password_verify($password, $hash)) {
                return true;
            }
        }

        return false;
    }
}
