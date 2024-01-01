(asdf:defsystem :3b-winmd
  :description "start of a parser for Windows .winmd metadata files, and ffi generator(s)"
  :version "0.0.1"
  :author "Bart Botta <00003b at gmail.com>"
  :license "MIT"
  :depends-on (alexandria binary-structures mmap cffi com-on)
  :serial t
  :components ((:file "package")
               (:file "parse")))


