// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import "C"

// Return codes for PCSC are different on different platforms (int vs. long).

type pcscRC C.int

func scCheck(rc C.int) error {
	if rc == rcSuccess {
		return nil
	}
	return &scErr{pcscRC(rc)}
}

func isRCNoReaders(rc C.int) bool {
	// MacOS does the right thing and doesn't return an error if no smart cards
	// are available.
	return false
}
