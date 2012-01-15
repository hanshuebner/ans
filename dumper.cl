(maphash #'(lambda (name node)
	     (format t "name: ~S node: ~S~%" name node)
	     (let ((hash (second node))
		   (maphash #'(lambda (key value)
				(format t "key: ~S value: ~S~%" key value))))))
	 (second n))





