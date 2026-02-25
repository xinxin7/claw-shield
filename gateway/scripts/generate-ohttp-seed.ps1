$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$seed = [Convert]::ToBase64String($bytes)

Write-Host "OHTTP_PRIVATE_KEY_SEED_B64=$seed"
Write-Host ""
Write-Host "Set it with:"
Write-Host "wrangler secret put OHTTP_PRIVATE_KEY_SEED_B64"
