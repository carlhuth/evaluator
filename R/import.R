#' Import the scenario spreadsheet.
#'
#' This is a wrapper function around \code{import_scenarios} and
#' \code{import_capabilities}, calling both functions and writing the dataframes
#' to a location on disk.
#'
#' @import dplyr
#' @param survey_file Path to survey XLSX file. Defaults to a sample file if not supplied.
#' @param domains Dataframe of domains and domain IDs. Defaults to built-in sample \code{domains} dataset.
#' @param output_dir Output file directory. Defaults to a \code{data}
#'   subdirectory in the current working direction.
#' @export
#' @return Dataframe of generated files (capabilities.csv and scenarios.csv)
import_spreadsheet <- function(survey_file = system.file("survey", "survey.xlsx", package = "evaluator"),
                               domains = NULL,
                               output_dir = "~/data"){

  ## ----survey_sheet--------------------------------------------------------
  #message("Target file is ", survey_file)

  # use default on domains if one is not passed in
  if (is.null(domains)) {
    utils::data(domains, package = "evaluator")
    domains <- domains
  }

  qualitative_scenarios <- import_scenarios(survey_file = survey_file,
                                            domains = domains)
  capabilities <- import_capabilities(survey_file = survey_file,
                                      domains = domains)

  ## ----write_files---------------------------------------------------------
  if (!dir.exists(output_dir)) dir.create(output_dir)
  readr::write_csv(capabilities, path = file.path(output_dir, "capabilities.csv"))
  readr::write_csv(qualitative_scenarios, path = file.path(output_dir, "qualitative_scenarios.csv"))

  file.info(c(file.path(output_dir, "capabilities.csv"),
              file.path(output_dir, "qualitative_scenarios.csv"))) %>%
    tibble::rownames_to_column("filename") %>% tibble::as_data_frame()
}

#' Import scenarios from survey spreadsheet.
#'
#' @import dplyr
#' @param survey_file Path to survey XLSX file. Defaults to a sample file if not supplied.
#' @param domains Dataframe of domains and domain IDs. Defaults to built-in sample \code{domains} dataset.
#' @export
#' @return Extracted qualitative scenarios as a dataframe.
import_scenarios <- function(survey_file = system.file("survey", "survey.xlsx", package = "evaluator"),
                               domains = NULL) {

  ## ----survey_sheet--------------------------------------------------------
  #message("Target file is ", survey_file)

  # use default domains if one is not passed in
  if (is.null(domains)) {
    utils::data(domains, package = "evaluator")
    domains <- domains
  }

  raw_domains <- domains %>%
    mutate_(raw_data = ~ purrr::map(domain_id, ~ readxl::read_excel(
      survey_file, skip=1, sheet=.)))

  ## ----walk_the_frame------------------------------------------------------
  raw_domains %>%
    mutate_(threats = ~ purrr::map(raw_data,
                                   ~ split_sheet(dat = .x,
                                                 table_type = "threats"))) %>%
    select_(~ -raw_data) -> dat

  # fetch and clean threats
  scenarios <- tidyr::unnest_(dat, "threats") %>%
    select_(scenario_id = "ScenarioID", scenario = "Scenario", tcomm = "TComm",
            tef = "TEF", tc = "TC", lm = "LM", "domain_id",
            controls = "Capabilities") %>%
    mutate_("scenario_id" = ~ as.integer(scenario_id)) %>% arrange_("scenario_id")

  scenarios <- mutate_at(scenarios, vars("tef", "lm", "tc"), funs(tolower)) # risk scenarios

  scenarios

}

#' Import capabilities from survey spreadsheet.
#'
#' @import dplyr
#' @param survey_file Path to survey XLSX file. Defaults to a sample file if not supplied.
#' @param domains Dataframe of domains and domain IDs. Defaults to built-in sample \code{domains} dataset.
#' @export
#' @return Extracted capabilities as a dataframe.
import_capabilities <- function(survey_file = system.file("survey", "survey.xlsx", package = "evaluator"),
                               domains = NULL){

  ## ----survey_sheet--------------------------------------------------------
  #message("Target file is ", survey_file)

  # use default domains if one is not passed in
  if (is.null(domains)) {
    utils::data(domains, package = "evaluator")
    domains <- domains
  }

  raw_domains <- domains %>%
    mutate_(raw_data = ~ purrr::map(domain_id, ~ readxl::read_excel(
      survey_file, skip=1, sheet=.)))

  ## ----walk_the_frame------------------------------------------------------
  raw_domains %>%
    mutate_(capabilities = ~ purrr::map(raw_data, split_sheet)) %>%
    select_(~ -raw_data) -> dat

  # fetch and clean capabilities
  capabilities <- tidyr::unnest_(dat, "capabilities") %>%
    select_(id = "CapabilityID", "domain_id", capability = "Name",
            diff = "DIFF") %>%
    mutate_("id" = ~ as.integer(id)) %>% arrange_("id")

  capabilities
}

#' Split a sheet of the survey spreadsheet into capabilities or threats.
#'
#' @import dplyr
#' @param dat Raw sheet input from \code{readxl}.
#' @param table_type Either \code{capabilities} or \code{threats}
#' @return Extracted table as a data_Frame
split_sheet <- function(dat, table_type = "capabilities") {
  # remote all NA rows
  dat <- dat[!!rowSums(!is.na(dat) != 0 ), ]
  # find the row where the threats table starts
  split_point <- which(dat$Name == "Threats")
  #message("Type is ", table_type)

  if (table_type == "capabilities") {
    # generate capabilities data
    capabilities_data <- dat[1:(split_point - 1), ]
    names(capabilities_data) <-
      make.names(
        names = names(capabilities_data),
        unique = TRUE,
        allow_ = TRUE
      )
    capabilities_data <- select(capabilities_data, matches("^[^X]"))
    capabilities_data
  } else {
    # generate threats_data
    threats_data <- dat[(split_point + 2):nrow(dat), ]
    names(threats_data) <-
      dat[(split_point + 1), ] %>% t %>% as.matrix() %>% as.vector()
    threats_data
  }
}
