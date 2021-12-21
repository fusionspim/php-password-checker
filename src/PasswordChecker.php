<?php
namespace FusionsPim\PhpPasswordChecker;

class PasswordChecker
{
    public const MINIMUM_MIN_LENGTH = 10;  // Tied to the filtered password-blacklist.txt (no data for less than 10 characters)

    public const REQUIRE_LOWERCASE = 'lowercase';
    public const REQUIRE_UPPERCASE = 'uppercase';
    public const REQUIRE_NUMBER    = 'number';
    public const REQUIRE_SYMBOL    = 'symbol';

    private int $minLength                = self::MINIMUM_MIN_LENGTH;
    private string|null $confirm          = null;
    private array|null $recentHashes      = null;
    private array $complexityRequirements = [];

    public function __construct(private array $rejectAsTooObvious = [])
    {
    }

    public function setConfirmation(string $confirm): void
    {
        $this->confirm = $confirm;
    }

    public function setPreviousPasswords(array $recentHashes = []): void
    {
        $this->recentHashes = $recentHashes;
    }

    public function setMinLength(int $minLength): void
    {
        if ($minLength >= self::MINIMUM_MIN_LENGTH) {
            $this->minLength = $minLength;
        }
    }

    public function setComplexityRequirements(array $requirements): void
    {
        $this->complexityRequirements = $requirements;
    }

    public function validate(string $password): bool
    {
        if (isset($this->confirm) && $this->confirm !== $password) {
            throw new PasswordException('New and confirmation passwords are different');
        }

        if (mb_strlen($password) < $this->minLength) {
            throw new PasswordException(sprintf('New password must be at least %d characters long', $this->minLength));
        }

        if ($this->isPasswordBlacklisted($password)) {
            throw new PasswordException('New password is too common, choose another');
        }

        if ($this->isPasswordObvious($password)) {
            throw new PasswordException('New password is too obvious, choose another');
        }

        if (isset($this->recentHashes) && $this->isRecentPassword($password)) {
            throw new PasswordException('New password has been used previously, choose another');
        }

        if (
            ! empty($this->complexityRequirements) &&
            ! empty($failedRequirements = $this->checkComplexityRequirements($password))
        ) {
            throw new PasswordException('New password should contain ' . $this->readableList($failedRequirements));
        }

        return true;
    }

    /**
     * @see: https://github.com/danielmiessler/SecLists/blob/master/Passwords/10_million_password_list_top_100000.txt
     * @note: All passwords with less than MIN_LENGTH characters have been removed from the file
     */
    private function isPasswordBlacklisted(string $password): bool
    {
        return in_array(mb_strtoupper($password), preg_split('/\v+/', mb_strtoupper(
            file_get_contents(__DIR__ . '/../resources/password-blacklist.txt')
        )), true);
    }

    private function isPasswordObvious(string $password): bool
    {
        foreach ($this->rejectAsTooObvious as $obvious) {
            if (mb_strpos(mb_strtolower($password), mb_strtolower($obvious)) !== false) {
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

    public function checkComplexityRequirements(string $password): array
    {
        $requirements = [
            [static::REQUIRE_LOWERCASE, '/[a-z]/', '1 lower case letter'],
            [static::REQUIRE_UPPERCASE, '/[A-Z]/', '1 upper case letter'],
            [static::REQUIRE_NUMBER, '/[\d]/', '1 number'],
            [static::REQUIRE_SYMBOL, '/[^a-zA-Z\d]/', '1 symbol'],
        ];

        $failures = [];

        foreach ($requirements as [$requirement, $regex, $description]) {
            if (in_array($requirement, $this->complexityRequirements, true) && ! preg_match($regex, $password)) {
                $failures[] = $description;
            }
        }

        return $failures;
    }

    private function readableList(array $items = [], string $join = 'and'): string
    {
        if (count($items) > 1) {
            return implode(', ', array_slice($items, 0, count($items) - 1)) . ' ' . $join . ' ' . $items[count($items) - 1];
        }

        return $items[0];
    }
}
