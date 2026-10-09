//! **Scripts as resources in any ikigai host.** A script is not a feature beside the
//! resources; it IS one, named `urn:script:{name}`, and every way of reaching it (a REST
//! door, the REPL, an MCP agent, a timer, a panel) is a door onto the same names.
//!
//! ```text
//! urn:script:{name}                    Source Exists Sink Delete  the script: fetch WITHOUT running, publish, retire
//! urn:script:{name}:version:{digest}   Source Exists              one immutable, content-addressed version
//! urn:script:{name}:compiled           Source                     the head prepared for its evaluator (cached)
//! urn:script:{name}:result             Source                     run it as a READ: its answer
//! urn:script:{name}:runs               Sink                       run it for EFFECTS: answers the run's IRI
//! urn:script:{name}:run:{id}           Source Exists              one recorded run
//! urn:script:eval                      Sink                       run supplied code under the caller's own authority
//! urn:script:catalog                   Source                     every script the caller may read
//! ```
//!
//! # A host library
//!
//! This crate binds no binary and mounts nowhere by itself. A host (`ikigai-embedded`,
//! gonk, the CMS) mounts [`space`] beside the evaluator it offers and decides the three
//! things only a host can — see [`SpaceConfig`]:
//!
//! - **where scripts live**: a [`Backend`] ([`MemoryBackend`], or [`DirBackend`] for plain
//!   files under a directory the host chooses);
//! - **the ceiling** each script may run under ([`authority::CeilingPolicy`], from the
//!   host's `<config home>/script-authority/{name}`);
//! - **who a request comes from** ([`authority::PrincipalStamper`]), recorded on every
//!   publish and run and never taken from the caller.
//!
//! ```
//! use ikigai_core::{Capability, Fallback, Kernel, Space};
//! use ikigai_script::{authority, space, MemoryBackend, SpaceConfig};
//! use std::sync::Arc;
//!
//! let scripts = space(SpaceConfig::new(
//!     Arc::new(MemoryBackend::new()),
//!     // Fail closed: a script the host has not given a ceiling may touch nothing.
//!     authority::same_for_all(authority::Ceiling::nothing()),
//! ));
//! // Beside the evaluator the scripts are written for (`ikigai_lisp::space()`):
//! let root = Fallback::new(vec![Arc::new(scripts) as Arc<dyn Space> /*, lisp, … */]);
//! let kernel = Kernel::new(Arc::new(root));
//! # let _ = (kernel, Capability::root());
//! ```
//!
//! # The authority rule
//!
//! Three authorities, never merged: **publish** (`urn:cap:script:write:{name}`, and
//! `…:delete:{name}` to retire), **run** (`urn:cap:script:run:{name}`, or
//! [`authority::CAP_RUN_PUBLIC`] for a public script), and **runs as**:
//!
//! ```text
//! runner's capability, attenuated to
//!   { declared } ∩ { what the publisher held at publish } ∩ { the host's ceiling }
//!   + every exclusion the publisher or the ceiling carries
//! ```
//!
//! **No elevation**: a publish declaring a scope its publisher does not hold is refused,
//! a run never holds anything its runner does not, and the only way a run's authority is
//! made is [`Invocation::issue_attenuated`](ikigai_core::Invocation::issue_attenuated) —
//! there is no form that widens. See [`authority`].
//!
//! # Languages are resources
//!
//! A run is a sub-request to the language's evaluator (`urn:lisp:eval` for Lisp, the only
//! language in this version), so this crate links no interpreter, and the evaluator's own
//! capability (`urn:cap:lisp`) is part of what every script declares: evaluating code is
//! itself authority.

#![deny(missing_docs)]

pub mod authority;
pub mod backend;
pub mod endpoints;
pub mod model;
pub mod name;

pub use backend::{Backend, DirBackend, MemoryBackend};
pub use endpoints::{space, Catalog, CatalogEntry, LastRun, Prepared, SpaceConfig};
pub use model::{Head, Language, Outcome, Run, State, Version};

/// The README's example, compiled (never run: it opens a directory) so it cannot rot.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
