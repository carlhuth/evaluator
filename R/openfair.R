# OpenFAIR components -----------------------------------------------------

#' Calculate the number of simulated threat event frequencies (TEF)
#'
#' @importFrom purrr invoke
#' @importFrom mc2d rpert
#' @param func Function to use to simulate TEF, defaults to mc2d::rpert
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("tef"), samples (as a vector), and details (as a list).
#' @export
sample_tef <- function(func = NULL, params = NULL) {
  if (is.null(func)) func <- get("rpert", asNamespace("mc2d"))
  list(type = "tef",
       samples = invoke(func, params),
       details = list())
}

#' Sample threat capabilities (TC) from a distribution function.
#'
#' @importFrom purrr invoke
#' @importFrom mc2d rpert
#' @param func Function to use to simulate TC, defaults to mc2d::rpert
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("tc"), samples (as a vector), and details (as a list).
#' @export
sample_tc <- function(func = NULL, params = NULL) {
  if (is.null(func)) func <- get("rpert", asNamespace("mc2d"))
  list(type = "tc",
       samples = invoke(func, params),
       details = list())
}

#' Calculate the difficulty for a loss event, given a function and parameters for that function.
#'
#' @importFrom purrr invoke
#' @importFrom purrr as_vector
#' @importFrom stats median
#' @importFrom mc2d rpert
#' @param func Function to use to simulate DIFF, defaults to mc2d::rpert
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("diff"), samples (as a vector), and details (as a list).
#' @export
sample_diff <- function(func = NULL, params = NULL) {
  if (is.null(func)) func <- get("rpert", asNamespace("mc2d"))
  list(type = "diff",
       samples = invoke(func, params),
       details = list())
}

#' Calculate the vulnerability
#'
#' @importFrom purrr invoke
#' @importFrom purrr is_list
#' @param func Function to use to simulate DIFF, defaults to `rbinom``
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("vuln"), samples (as a vector), and details (as a list).
#' @export
sample_vuln <- function(func = NULL, params = NULL) {
  if (is.null(func)) func <- get("rbinom", asNamespace("stats"))
  dat <- invoke(func, params)
  list(type = "vuln",
       samples = if(purrr::is_list(dat)) dat$samples else dat,
       details = if(purrr::is_list(dat)) dat$details else list()
  )
}

#' Given a number of loss events and a loss distribution, calculate losses
#'
#' @importFrom purrr invoke
#' @importFrom purrr rerun
#' @importFrom purrr as_vector
#' @importFrom stats median
#' @importFrom mc2d rpert
#' @param n Number of loss events to simulate. Defaults to 0.
#' @param func Function to use to simulate TEF, defaults to mc2d::rpert.
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("lm"), samples (as a vector), and details (as a list).
#' @export
sample_lm <- function(n = 0, func = NULL, params = NULL) {

  if (is.null(func)) func <- get("rpert", asNamespace("mc2d"))
  if (is.na(n)) { n <- 0 }
  samples <- purrr::as_vector(purrr::rerun(n, invoke(func, params)))

  # We have to calculate ALE/SLE differently (ALE: 0, SLE: NA) if there are no losses
  details <- if (length(samples) == 0) {
      list(ale = 0, sle_max = 0, sle_min = 0, sle_mean = 0, sle_median = 0)
  } else {
      list(ale = sum(samples),
           sle_max = max(samples),
           sle_min = min(samples[samples > 0]),
           sle_mean = mean(samples[samples > 0]),
           sle_median = stats::median(samples[samples > 0])
           )
    }

    return(list(type = "lm", samples = samples, details = details))
}

#' Sample loss event frequency
#'
#' @importFrom purrr invoke
#' @importFrom purrr is_list
#' @param func Function to use to simulate LEF, defaults to `rnorm``
#' @param params Optional parameters to pass to `func`
#' @return List containing type ("diff"), samples (as a vector), and details (as a list).
#' @export
sample_lef <- function(func = NULL, params = NULL) {
  if (is.null(func)) func <- get("rnorm", asNamespace("stats"))
  dat <- invoke(func, params)
  list(type = "lef",
       samples = if(purrr::is_list(dat)) dat$samples else dat,
       details = if(purrr::is_list(dat)) dat$details else list()
  )
}

# Composition Functions ---------------------------------------------------

#' Calculate number of loss events
#'
#' Composition function for use in sample_lef. Given a number of threat
#' events (tef), calculate how many of those become loss events (lef)
#' by taking a straight percentge (vuln).
#'
#' @param tef Threat event frequency (n)
#' @param vuln Vulnerability (percentage)
#' @return List containing samples (as a vector) and details (as a list)
#' @export
compare_tef_vuln <- function(tef, vuln) {
  samples = tef * vuln
  list(samples = samples,
       details = list())
}

#' Calculate the vulnerability
#'
#' Composition function for use in sample_vuln, does a simple compare of
#' all occurances where the threat capability (TC) is greater than the
#' difficulty (DIFF).
#'
#' @param tc Threat capability (as a percentage)
#' @param diff Difficult (as a percentage)
#' @return List containing samples (as a vector) and details (as a list)
#' @export
detail_vuln <- function(tc, diff) {
  samples = tc > diff
  list(samples = samples,
       details = list(mean_tc_exceedance = mean(tc[samples] - diff[samples]),
                      mean_diff_exceedance = mean(diff[!samples] - tc[!samples])))
}

# Top Level Analysis ------------------------------------------------------

#' Run an OpenFAIR simulation
#'
#' @import dplyr bind_rows
#' @importFrom purrr mapf
#' @importFrom purrr map_df
#' @importFrom tibble as_data_frame
#' @param scenario list of tef_, tc_, and LM_ l/ml/h/conf parameters
#' @param diff_estimates parameters for estimating the scenario difficulty
#' @param n Number of simulations to run
#' @param title Optional name of scenario
#' @param verbose Whether to print progress indicators
#' @return Dataframe of scenario name, threat_event count, loss_event count,
#'   mean TC and DIFF exceedance, and ALE samples
#' @export
calculate_ale <- function(scenario, diff_estimates = NULL, n = 10^4,
                          title = "Untitled", verbose = FALSE) {

    # make samples repeatable (and l33t)
    set.seed(31337)

    if (verbose) {
        message("Working on scenario ", title)
        message(paste("Scenario is: ", scenario[, -which(names(scenario) %in% "diff_samples")], "\n"))
        # message(paste('Names are ', names(scenario)))
    }

    # TEF - how many contacts do we have in each simulated year
    TEFestimate <- with(scenario, tibble::tibble(l = tef_l, ml = tef_ml,
                                                 h = tef_h, conf = tef_conf))
    TEFsamples <- sample_tef(params = list(n, TEFestimate$l, TEFestimate$ml,
                                           TEFestimate$h,
                                           shape = TEFestimate$conf))
    TEFsamples <- round(TEFsamples$samples)

    # TC - what is the strength of each threat event
    TCestimate <- with(scenario, tibble::tibble(l = tc_l, ml = tc_ml,
                                                h = tc_h, conf = tc_conf))
    TCsamples <- sample_tc(params = list(n, TCestimate$l, TCestimate$ml,
                                         TCestimate$h, shape = TCestimate$conf))
    TCsamples <- TCsamples$samples

    # DIFF - calculate the mean strength of controls
    DIFFestimate <- diff_estimates
    DIFFsamples <- purrr::pmap_df(list(n, DIFFestimate),
                                  sample_diff(params = list(n, a, b, c, d)$samples))
    # if we were supplied an array of controls, take the mean for the
    #   effective control strength across the scenario
    DIFFsamples <- if(is.array(DIFFsamples)) rowMeans(DIFFsamples) else mean(DIFFsamples)

    # LEF - determine how many threat events become losses (TC > DIFF)
    LEFsamples <- purrr::map(TEFsamples, ~ { sample_lef(
      func = compare_tef_vuln, params = list(tef = .x, vuln = vulns)})
    mean_tc_exceedance <- LEFsamples$details$mean_tc_exceedance
    mean_diff_exceedance <- LEFsamples$details$mean_diff_exceedance

    # LM - determine the size of losses for each simulation
    loss_samples <- purrr::map_df(
      LEFsamples$samples, ~ { sample_lm(params =
                                          list(.x, LMestimate$l, LMestimate$ml,
                                               LMestimate$h, LMestimate$conf))$details)})
    loss_samples <- dplyr::bind_rows(loss_samples)

    # summary stats for ALE
    if (verbose) {
        print(summary(loss_samples$samples))
        value_at_risk <- quantile(loss_samples$samples, probs = (0.95))
        message(paste0("Losses at 95th percentile are $",
                       format(value_at_risk, nsmall = 2, big.mark = ",")))
    }

    tibble::tibble(title = rep(as.character(title), n),
                   simulation = seq(1:n),
                   threat_events = TEFsamples,
                   loss_events = LEFsamples,
                   mean_tc_exceedance = mean_tc_exceedance,
                   mean_diff_exceedance = mean_diff_exceedance,
                   ale = loss_samples$samples,
                   sle_max = loss_samples$details$sle_max,
                   sle_min = loss_samples$details$sle_min,
                   sle_mean = loss_samples$details$sle_mean,
                   sle_median = loss_samples$details$sle_median)
}
