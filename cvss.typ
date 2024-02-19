// Copyright 2024 Thomas Gingele https://github.com/B1TC0R3

#import "@preview/plotst:0.2.0": *

/*
 * Turn a CVSS vector from a string into a dictionary of numerical values.
 * Required for further calculations.
 */
#let parse-cvss-vector(vector) = {
  // Specification: https://www.first.org/cvss/v3.1/specification-document
  let mapping = (
    AV : (
      N: 0.85,
      A: 0.62,
      L: 0.55,
      P: 0.2,
    ),
    AC: (
      L: 0.77,
      H: 0.44,
    ),
    PR: (
      N: 0.85,
      L: 0.62,
      P: 0.27,
    ),
    UI: (
      N: 0.85,
      R: 0.62,
    ),
    S: (
      U: 0,
      C: 1,
    ),
    C: (
      N: 0,
      L: 0.22,
      H: 0.56,
    ),
    I: (
      N: 0,
      L: 0.22,
      H: 0.56,
    ),
    A: (
      N: 0,
      L: 0.22,
      H: 0.56,
    ),
    E: (
      X: 1,
      U: 0.91,
      P: 0.94,
      F: 0.97,
      H: 1,
    ),
    RL: (
      X: 1,
      O: 0.95,
      T: 0.96,
      W: 0.97,
      U: 1,
    ),
    RC: (
      X: 1,
      U: 0.92,
      R: 0.96,
      C: 1,
    )
  )

  let category = ""
  let letter   = ""
  let number   = 0
  let parsed_vector = (AV: 0.85, AC: 0.77, PR: 0.85, UI: 0.85, S: 1, C: 0.56, I: 0.56, A: 0.56, E: 1, RL: 1, RC: 1)
  
  vector = vector.split("/")
  
  for value in vector {
    category = value.split(":").at(0)
    letter   = value.split(":").at(1) 

    number = mapping.at(category).at(letter) 

    // Special case where value of 'privileges required' changes when scope 
    // change is possible
    if category == "PR" {
      if vector.contains("S:C") {
        if letter == "L" {
          number = 0.68
        } else if letter == "P" {
          number = 0.5
        }
      }
    }
    
    parsed_vector.insert(
      category,
      mapping.at(category).at(letter)
    )
  }

  return parsed_vector
}

/*
 * Round up values to the next higher d-th deciaml.
 * Example:
 *
 * round-up(1.84, 1) = 1.9
 */
#let round-up(x, d) = {
  let decimal = calc.pow(10, d)
  
  x = x * decimal
  x = calc.ceil(x)
  
  return x / decimal
}

/*
CVSS v3.1 Equations

The CVSS v3.1 equations are defined below.
Base

The Base Score is a function of the Impact and Exploitability sub score equations. Where the Base score is defined as,
    If (Impact sub score <= 0)     0 else,
    Scope Unchanged4                 𝑅𝑜𝑢𝑛𝑑𝑢𝑝(𝑀𝑖𝑛𝑖𝑚𝑢𝑚[(𝐼𝑚𝑝𝑎𝑐𝑡 + 𝐸𝑥𝑝𝑙𝑜𝑖𝑡𝑎𝑏𝑖𝑙𝑖𝑡𝑦), 10])
    Scope Changed                      𝑅𝑜𝑢𝑛𝑑𝑢𝑝(𝑀𝑖𝑛𝑖𝑚𝑢𝑚[1.08 × (𝐼𝑚𝑝𝑎𝑐𝑡 + 𝐸𝑥𝑝𝑙𝑜𝑖𝑡𝑎𝑏𝑖𝑙𝑖𝑡𝑦), 10])

and the Impact sub score (ISC) is defined as,

    Scope Unchanged 6.42 × 𝐼𝑆𝐶Base
    Scope Changed 7.52 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.029] − 3.25 × [𝐼𝑆𝐶𝐵𝑎𝑠𝑒 − 0.02]15

Where,

    𝐼𝑆𝐶𝐵𝑎𝑠𝑒 = 1 − [(1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐶𝑜𝑛𝑓) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐼𝑛𝑡𝑒𝑔) × (1 − 𝐼𝑚𝑝𝑎𝑐𝑡𝐴𝑣𝑎𝑖𝑙)]

 And the Exploitability sub score is,

    8.22 × 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜𝑛
*/

#let impact(s, c, i, a) = {
  let isc      = 0
  let isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
  
  if (s == 0) {
    isc = 6.42 * isc_base 
    
  } else if (s == 1) {
    isc = (7.52 * (isc_base - 0.029)) - (3.25 * (calc.pow((isc_base - 0.02), 15)))
    
  }

  return isc
}

#let exploitability(av, ac, pr, ui) = {
  return 8.22 * av * ac * pr * ui
}

#let base-cvss-score(
  av: 0, 
  ac: 0, 
  pr: 0, 
  ui: 0, 
  s : 0, 
  c : 0, 
  i : 0, 
  a : 0,
) = {
  let score = 0
  let isc   = impact(s, c, i, a)
  let esc   = exploitability(av, ac, pr, ui)

  if (isc > 0) {
    if (s == 0) {
      score = round-up(calc.min((isc + esc), 10), 1)

    } else if (s == 1) {
      score = round-up(calc.min((1.08 * (isc + esc)), 10), 1)  
      
    }
  }

  return score
}

/*
Temporal
The Temporal score is defined as,

    𝑅𝑜𝑢𝑛𝑑𝑢𝑝(𝐵𝑎𝑠𝑒𝑆𝑐𝑜𝑟𝑒 × 𝐸𝑥𝑝𝑙𝑜𝑖𝑡𝐶𝑜𝑑𝑒𝑀𝑎𝑡𝑢𝑟𝑖𝑡𝑦 × 𝑅𝑒𝑚𝑒𝑑𝑖𝑎𝑡𝑖𝑜𝑛𝐿𝑒𝑣𝑒𝑙 × 𝑅𝑒𝑝𝑜𝑟𝑡𝐶𝑜𝑛𝑓𝑖𝑑𝑒𝑛𝑐𝑒)
*/
#let temporal-cvss-score(
  base_score:10,
  e : 0,
  rl: 0,
  rc: 0
) = {
  return round-up(base_score * e * rl * rc, 1)
}

/*
Environmental
The environmental score is defined as,

    If (Modified Impact Sub score <= 0)     0 else,

    If Modified Scope is Unchanged           Round up(Round up (Minimum [ (M.Impact + M.Exploitability) ,10]) × Exploit Code Maturity × Remediation Level × Report Confidence)
    
    If Modified Scope is Changed               Round up(Round up (Minimum [1.08 × (M.Impact + M.Exploitability) ,10]) × Exploit Code Maturity × Remediation Level × Report Confidence)

And the modified Impact sub score is defined as,

    If Modified Scope is Unchanged 6.42 × [𝐼𝑆𝐶𝑀𝑜𝑑𝑖𝑓𝑖𝑒𝑑]
    
    If Modified Scope is Changed 7.52 × [𝐼𝑆𝐶𝑀𝑜𝑑𝑖𝑓𝑖𝑒𝑑 − 0.029]-3.25× [𝐼𝑆𝐶𝑀𝑜𝑑𝑖𝑓𝑖𝑒𝑑 × 0.9731 − 0.02] 13

Where,
    𝐼𝑆𝐶𝑀𝑜𝑑𝑖𝑓𝑖𝑒𝑑 = 𝑀𝑖𝑛𝑖𝑚𝑢𝑚 [[1 − (1 − 𝑀. 𝐼𝐶𝑜𝑛𝑓 × 𝐶𝑅) × (1 − 𝑀. 𝐼𝐼𝑛𝑡𝑒𝑔 × 𝐼𝑅) × (1 − 𝑀. 𝐼𝐴𝑣𝑎𝑖𝑙 × 𝐴𝑅)], 0.915]

The Modified Exploitability sub score is,

    8.22 × 𝑀. 𝐴𝑡𝑡𝑎𝑐𝑘𝑉𝑒𝑐𝑡𝑜𝑟 × 𝑀. 𝐴𝑡𝑡𝑎𝑐𝑘𝐶𝑜𝑚𝑝𝑙𝑒𝑥𝑖𝑡𝑦 × 𝑀. 𝑃𝑟𝑖𝑣𝑖𝑙𝑒𝑔𝑒𝑅𝑒𝑞𝑢𝑖𝑟𝑒𝑑 × 𝑀. 𝑈𝑠𝑒𝑟𝐼𝑛𝑡𝑒𝑟𝑎𝑐𝑡𝑖𝑜n
*/
#let environmental-cvss-score() = {
  assert(false, "Environmental CVSS score not yet implemented!")
  //For later: PR values changes when modified scope is set to 'changed'!
}

/*
 * Wrapper function for score calculation. Will return base score, temporal score,
 * impact and exploitability as a dictionary.
 */
#let all_scores(vector) = {
  let parsed_vector= parse-cvss-vector(vector)

  let impact = impact(
    parsed_vector.S,
    parsed_vector.C,
    parsed_vector.I,
    parsed_vector.A,
  )

  let exploitability = exploitability(
    parsed_vector.AV,
    parsed_vector.AC,
    parsed_vector.PR,
    parsed_vector.UI,
  )
  
  let base_cvss_score = base-cvss-score(
    ac: parsed_vector.AV,
    av: parsed_vector.AC,
    pr: parsed_vector.PR,
    ui: parsed_vector.UI,
    s: parsed_vector.S,
    c: parsed_vector.C,
    i: parsed_vector.I,
    a: parsed_vector.A,
  )

  let temporal_cvss_score = temporal-cvss-score(
    base_score: base_cvss_score,
    e: parsed_vector.E,
    rl: parsed_vector.RL,
    rc: parsed_vector.RC
  )

  return (
    base          : base_cvss_score,
    temporal      : temporal_cvss_score,
    impact        : impact,
    exploitability: exploitability,
  )
}

/*
 * Small function to assign colors to the severity of a vulnerability.
 */
#let color_from_severity(severity) = {

  if severity >= 9 { // Critical
    return red
  } else if severity > 6.9 { // High
    return orange 
  } else if severity > 3.9 { // Medium
    return yellow
  } else if severity > 0 { // Low
    return green
  }

  return gray // No vulnerability
}

/*
 * Parse a CVSS v3.1 vector into a clickable link and automatically calulate the score.
 *
 */
#let cvss(vector) = {
  let cvss_calculator_url = "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator"
  let cvss_version        = "3.1"
  let cvss_result_link    = cvss_calculator_url + "?vector=" + vector + "&version=" + cvss_version

  let cvss_data = all_scores(vector)
  
  let plot_data = (
    (cvss_data.base, "Base"),
    (cvss_data.impact, "Impact"),
    (cvss_data.exploitability, "Exploitability"),
    (cvss_data.temporal, "Temporal"),
  )
  
  let x_axis = axis(
    values: (
      "", 
      "Base",
      "Impact",
      "Exploitability",
      "Temporal",
    ),
    location: "bottom",
  )
  
  let y_axis = axis(
    min: 0, 
    max: 12, 
    step: 2, 
    location: "left",
    helper_lines: true,
  )
  
  let cvss_plot   = plot(
    axes: (x_axis, y_axis),
    data: plot_data
  )
  
  box(
    stroke: black,
    width:100%,
    radius: 5pt,
    inset: 10pt,
    [
      #grid(
        columns: (auto, auto),
        rows   : (auto),
        column-gutter: 5pt,
        row-gutter: 7pt,
        [*Vector*:], link(cvss_result_link)[#vector]
      )
      #grid(
        columns: (auto, 50pt, auto, 50pt, auto, auto),
        rows   : (auto, auto),
        column-gutter: 5pt,
        row-gutter: 7pt,
        [*Base Score:*],     [#cvss_data.base], 
        [*Impact:*],         [#calc.round(cvss_data.impact, digits: 1)],
        [*Exploitability:*], [#calc.round(cvss_data.exploitability, digits: 1)],
        [*Temporal Score:*],  [#cvss_data.temporal],
      )
      
      #bar_chart(
        cvss_plot,
        (100%,20%),
        bar_width: 50%,
        fill: (
          color_from_severity(cvss_data.base),
          color_from_severity(cvss_data.impact),
          color_from_severity(cvss_data.exploitability),
          color_from_severity(cvss_data.temporal)
        ),
        caption: none
      )
    ]
  )
}