(defun dumpnode (prefix name node)
  (progn
    (format t "~Aname: ~S node: ~%" prefix name node)
    (setq prefix (format nil " ~A" prefix))
    (maphash #'(lambda (key value)
		 (format t "~Aname: ~S node: ~%" prefix key value)
		 (if (not (= 0 (hash-table-count (second value))))
		     (dumpnode prefix key value)))
	     (second node))))

(dumpnode "" "start" *db*)
