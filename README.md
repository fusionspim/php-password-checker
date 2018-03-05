# PHP Password Checker

Passwords must be at least 10 characters in length and not be commonly used - there's no means to override this.

Numeric *looking* passwords are rejected, to weed out obvious memorable dates and phone numbers.

All password checks are **case insensitive**.

```
$checker = new PasswordChecker;
$checker->validate('abc123'); // throws PasswordException (too short)
$checker->validate('password123'); // throws PasswordException (too common)
$checker->validate('123-456-7890'); // throws PasswordException (too numeric)
$checker->validate('31/12/1999'); // throws PasswordException (too numeric)
$checker->validate('we love php'); // returns true
```

That's it. Though you can add further (optional, but recommended) checks and restrictions...

### Password reuse

Prevent password reuse by storing previous password hashes in your application and passing them in:

```
$checker = new PasswordChecker;
$checker->setPreviousPasswords($arrayOfHashes); // generated from password_hash()
$checker->validate($userSuppliedPassword);
```

### Password confirmation

If you ask users to confirm their new password, you can pass that in too - simply to have all checks handled consistently:

```
$checker = new PasswordChecker;
$checker->setConfirmation($userSuppliedConfirmation);
$checker->validate($userSuppliedPassword);
```

### User or application obvious

Provide a blacklist of words that are obvious in the context of the user/application. If they're **within** (i.e. not necessarily equal to) the user supplied password, validation will fail:

```
$checker = new PasswordChecker(['clem', 'fandango', 'MyAmazingApp');
$checker->validate('myamazingapp'); // throws PasswordException
$checker->validate('myamazingapp123'); // throws PasswordException
$checker->validate('clemfandango'); // throws PasswordException
$checker->validate('fandango123'); // throws PasswordException
```
