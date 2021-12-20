<?php
$config = FusionsPim\PhpCsFixer\Factory::fromDefaults();

return $config->setFinder(
    $config->getFinder()
        ->notName('rector.php')
);
