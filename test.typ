#{
import "cvss.typ": *

//round-up()
assert(round-up(1.81, 1) == 1.9)
assert(round-up(1.89, 1) == 1.9)
assert(round-up(1.99, 1) == 2.0)
assert(round-up(-1,   1) == -1)
assert(round-up(1,    0) == 1)

//impact()
assert(impact(0, 1, 1, 1) == 6.42)
assert(impact(1, 1, 1, 1) == 4.901570416402437)
assert(impact(0, 0.5, 0.5, 0.5) == 5.6175)

//exploitability()
assert(exploitability(1, 1, 1, 1) == 8.22)
assert(exploitability(0.5, 0.5, 0.5, 0.5) == 0.51375)

//base-cvss-score()
assert(base-cvss-score(1, 1, 1, 1, 0, 1, 1, 1) == 10)
assert(base-cvss-score(1, 1, 1, 1, 1, 1, 1, 1) == 10)
assert(base-cvss-score(0.5, 0.5, 0.5, 0.5, 0, 0.5, 0.5, 0.5) == 6.2)
assert(base-cvss-score(0.5, 0.5, 0.5, 0.5, 1, 0.5, 0.5, 0.5) == 7.1)

//temporal-cvss-score()
assert(temporal-cvss-score(10, 1, 1, 1) == 10)
assert(temporal-cvss-score(4.9, 0.91, 0.95, 0.92) == 3.9)

//modified-impact()
assert(modified-impact(0, 1, 1, 1, 1, 1, 1) == 5.8743)
assert(modified-impact(1, 1, 1, 1, 1, 1, 1) == 6.127981733934466)
assert(modified-impact(0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5) == 3.7115625)
assert(modified-impact(1, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5) == 4.128272258116485)

//environmental-cvss-score
//TODO
}
