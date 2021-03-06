% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/openfair.R
\name{calculate_ale}
\alias{calculate_ale}
\title{Run an OpenFAIR simulation}
\usage{
calculate_ale(scenario, diff_samples = NULL, diff_estimates = NULL,
  n = 10^4, title = "Untitled", verbose = FALSE)
}
\arguments{
\item{scenario}{list of tef_, tc_, and LM_ l/ml/h/conf parameters}

\item{diff_samples}{Sampled difficulties for the scenario (DEPRECATED)}

\item{diff_estimates}{Sampled difficulties for the scenario}

\item{n}{Number of simulations to run}

\item{title}{Optional name of scenario}

\item{verbose}{Whether to print progress indicators}
}
\value{
Dataframe of scenario name, threat_events count, loss_events count,
  mean TC and DIFF exceedance, and ALE samples
}
\description{
Run an OpenFAIR simulation
}
