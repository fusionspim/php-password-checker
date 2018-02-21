<?php
namespace FusionsPim\PhpPasswordChecker;

class PasswordChecker
{
    const MIN_LENGTH = 10; // Fixed to align with password-blacklist.txt

    private $errorMessage;
    private $rejectAsTooObvious;

    public function __construct(array $rejectAsTooObvious = [])
    {
        $this->rejectAsTooObvious = $rejectAsTooObvious;
    }

    public function validate(string $password, array $recentHashes = []): bool
    {
        if (mb_strlen($password) < static::MIN_LENGTH) {
            $this->errorMessage = sprintf('New password must be at least %d characters long', static::MIN_LENGTH);
        } elseif ($this->isPasswordBlacklisted($password)) {
            $this->errorMessage = 'New password is too common, choose another';
        } elseif ($this->isPasswordObvious($password)) {
            $this->errorMessage = 'New password is too obvious, choose another';
        } elseif ($this->isRecentPassword($password, $recentHashes)) {
            $this->errorMessage = 'New password has been used previously, choose another';
        }

        return is_null($this->errorMessage);
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

    private function isRecentPassword(string $password, array $recentHashes = []): bool
    {
        foreach ($recentHashes as $hash) {
            if (password_verify($password, $hash)) {
                return true;
            }
        }

        return false;
    }

    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }
}
