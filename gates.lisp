(defpackage :gates
  (:use :cl)
  (:export #:make-gate
           #:open-gate
           #:close-gate
           #:wait-open-gate
           #:gate-open-p))

(in-package :gates)

;;;; Gates from http://common-lisp.net/~trittweiler/darcs/synchronization-tools/synchronization-tools.lisp
;;;; Adapted to bordeaux-threads by hans.huebner@gmail.com

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defconstant +gate-open+ 0)
  (defconstant +gate-closed+ 1))

(defun missing-arg ()
  (error "missing argument"))

(defstruct (gate (:constructor %make-gate))
  (lock (missing-arg))
  (waitq (missing-arg))
  (state +gate-closed+ :type fixnum)
  (name nil :type (or null simple-string)))

(defmethod print-object ((gate gate) stream)
  (print-unreadable-object (gate stream :type t :identity t)
    (format stream "~@[~S ~](~S)"
            (gate-name gate)
            (case (gate-state gate)
              (#.+gate-open+   :open)
              (#.+gate-closed+ :closed)
              (t "<invalid state>")))))

(defun make-gate (&key name)
  (flet ((generate-name (thing)
           (when name
             (format nil "gate ~S's ~A" name thing))))
    (%make-gate
     :name name
     :lock (bt:make-lock (generate-name "lock"))
     :waitq (bt:make-condition-variable :name (generate-name "condition variable"))
     :state +gate-closed+)))

(defun open-gate (gate)
  (declare (gate gate))
  (bt:with-lock-held ((gate-lock gate))
    (setf (gate-state gate) +gate-open+)
    (bt:condition-notify (gate-waitq gate)))
  gate)

(defun close-gate (gate)
  (declare (gate gate))
  (bt:with-lock-held ((gate-lock gate))
    (setf (gate-state gate) +gate-closed+))
  gate)

(defun wait-open-gate (gate)
  (declare (gate gate))
  (bt:with-lock-held ((gate-lock gate))
    (loop while (not (gate-open-p gate))
          do (bt:condition-wait (gate-waitq gate) (gate-lock gate))))
  gate)

(defun gate-open-p (gate)
  (declare (gate gate))
  (eql (gate-state gate) +gate-open+))