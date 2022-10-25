# by Jared Atkinson (@jaredcatkinson)
function Measure-DamerauLevenshteinDistance {

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Original,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $Modified
    )

    if ($original -eq $modified)
    {
        return 0
    }

    $len_orig = $original.Length
    $len_diff = $modified.Length

    if ($len_orig -eq 0)
    {
        return $len_diff
    }

    if ($len_diff -eq 0)
    {
        return $len_orig
    }

    $matrix = New-Object -TypeName 'object[,]' ($len_orig + 1), ($len_diff + 1)

    for ($i = 1; $i -le $len_orig; $i++)
    {
        $matrix[$i,0] = $i

        for ($j = 1; $j -le $len_diff; $j++)
        {
            if ($modified[$j - 1] -eq $original[$i - 1])
            {
                $cost = 0
            }
            else
            {
                $cost = 1
            }

            if ($i -eq 1)
            {
                $matrix[0,$j] = $j
            }

            $v1 = $matrix[($i - 1), $j] + 1
            $v2 = $matrix[$i, ($j - 1)] + 1
            $v3 = $matrix[($i - 1), ($j - 1)] + $cost
            $vals = @($v1, $v2, $v3)

            $matrix[$i,$j] = ($vals | Measure-Object -Minimum).Minimum

            if (($i -gt 1) -and ($j -gt 1) -and ($original[$i - 1] -eq $modified[$j - 2]) -and ($original[$i - 2] -eq $modified[$j - 1]))
            {
                $val1 = $matrix[$i, $j]
                $val2 = $matrix[($i - 2), ($j - 2)] + $cost
                $matrix[$i, $j] = [Math]::Min($val1, $val2)
            }
        }
    }
    return $matrix[$len_orig, $len_diff]

}
