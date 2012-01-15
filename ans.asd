;; -*- Lisp -*-

(defsystem :ans
  :serial t
  :depends-on (:usocket
               :bordeaux-threads
               :cl-ppcre)
  :description "Domain Name Server"
  :components ((:file "gates")
               (:file "ans")))