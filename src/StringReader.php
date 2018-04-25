<?php declare(strict_types=1);

namespace Milo\Net;


class StringReader
{
	/** @var string */
	public $length;

	/** @var resource */
	private $stream;


	public function __construct($data)
	{
		$this->stream = \fopen('php://memory', 'wb+');
		\fwrite($this->stream, $data);
		\rewind($this->stream);
		$this->length = \strlen($data);
	}


	public function read(int $length): string
	{
		return $length > 0
			?  \fread($this->stream, $length)
			: '';
	}


	public function readRest(): string
	{
		return \stream_get_contents($this->stream);
	}
}
